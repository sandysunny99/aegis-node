"""
Aegis Node — Threat-intelligence enrichment of a completed local scan.

Extracted from the scan endpoint (C5). Order of operations:
  1. VirusTotal hash lookup (only the SHA-256 leaves the server), kept as TI evidence.
  2. Indicator extraction from the file: public URLs and IPv4 addresses, read in
     bounded chunks in a worker thread (C4) so a 50 MB upload never blocks the
     event loop or gets loaded into memory at once.
  3. URLhaus / AbuseIPDB reputation for at most MAX_INDICATORS of each.
  4. Deterministic fusion; the local scanner verdict is never overridden.

Per AGENTS.md, only hashes, URLs and IPs are sent to providers (never dataset
rows), URLs are never fetched, and every provider is opt-in (config defaults OFF).
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from config import settings
from fastapi.concurrency import run_in_threadpool
from schemas import NormalizedTIEvidence, TIFusionReport

from services.threat_intelligence import lookups
from services.threat_intelligence.abuseipdb import lookup_ip
from services.threat_intelligence.fusion import evaluate_local_verdict_conflict, fuse_reports
from services.threat_intelligence.urlhaus import lookup_url
from services.threat_intelligence.virustotal import lookup_file_hash

logger = logging.getLogger(__name__)

MAX_INDICATORS = 5
_CHUNK_BYTES = 1024 * 1024
_OVERLAP_BYTES = 4096  # carry-over so an indicator split across chunks is still seen

# Delimiters (, ; |) end a URL: in CSV/TSV-like data the next cell must never be
# glued onto the indicator and sent to a provider (AGENTS.md: no dataset rows out).
_URL_RE = re.compile(rb"https?://[a-zA-Z0-9.-]+(?:/[^\s\"'<>,;|]*)?", re.IGNORECASE)
_IPV4_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_UNAVAILABLE = ("timeout", "rate_limited", "provider_error", "unauthorized", "forbidden")

# Adapter status strings -> one documented result state (docs/THREAT_INTEL_API_CONTRACT.md).
_RESULT_STATES = {
    "malicious": "MATCH",
    "suspicious": "MATCH",
    "clean": "NO_MATCH",
    "not_found": "NO_MATCH",
    "timeout": "TIMEOUT",
    "rate_limited": "RATE_LIMITED",
    "unauthorized": "UNAUTHORIZED",
    "forbidden": "UNAUTHORIZED",
    "provider_error": "UNAVAILABLE",
}


def result_state(status: str) -> str:
    """Normalised state for an adapter status; anything unexpected is INVALID_RESPONSE."""
    return _RESULT_STATES.get(status, "INVALID_RESPONSE")


@dataclass
class Indicators:
    urls: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)


def extract_indicators(path: str | Path, limit: int = MAX_INDICATORS) -> Indicators:
    """
    Return the first `limit` distinct URLs and IPv4 strings in file order.
    Streams the file in 1 MB chunks and stops as soon as both lists are full.
    """
    found = Indicators()
    tail = b""
    with open(path, "rb") as fh:
        chunk = fh.read(_CHUNK_BYTES)
        while chunk and (len(found.urls) < limit or len(found.ips) < limit):
            next_chunk = fh.read(_CHUNK_BYTES)  # look ahead so we know when this is the last chunk
            at_eof = not next_chunk
            window = tail + chunk
            for pattern, bucket in ((_URL_RE, found.urls), (_IPV4_RE, found.ips)):
                for match in pattern.finditer(window):
                    if len(bucket) >= limit:
                        break
                    if not at_eof and match.end() == len(window):
                        continue  # may be cut off by the chunk edge; seen whole next round
                    try:
                        value = match.group().decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    if value not in bucket:
                        bucket.append(value)
            tail = window[-_OVERLAP_BYTES:]
            chunk = next_chunk
    return found


def _url_evidence(url: str, intel) -> NormalizedTIEvidence:
    error_status = intel.status if intel.status in _UNAVAILABLE else None
    if error_status:
        rep, sev = "unknown", "informational"
    elif intel.status == "malicious":
        rep, sev = "malicious", "critical"
    elif intel.status in ("clean", "not_found"):
        # No URLhaus entry (or an entry with no known threat) says nothing about safety:
        # it is a no-match, never "benign" (Phase B3).
        rep, sev = "unknown", "informational"
    else:
        rep, sev = "unknown", "low"
    return NormalizedTIEvidence(
        provider="urlhaus",
        indicator_type="url",
        indicator=url,
        reputation=rep,
        confidence=intel.confidence,
        severity=sev,
        category=intel.tags[0] if intel.tags else None,
        reference_url=intel.raw_reference,
        error_status=error_status,
        result_state=result_state(intel.status),
    )


def _ip_evidence(ip: str, intel) -> NormalizedTIEvidence:
    error_status = intel.status if intel.status in _UNAVAILABLE else None
    if error_status:
        rep, sev = "unknown", "informational"
    elif intel.status == "malicious":
        rep, sev = "malicious", "critical"
    elif intel.status == "suspicious":
        rep, sev = "suspicious", "high"
    elif intel.status == "clean":
        rep, sev = "benign", "informational"
    else:
        rep, sev = "unknown", "low"
    return NormalizedTIEvidence(
        provider="abuseipdb",
        indicator_type="ipv4",
        indicator=ip,
        reputation=rep,
        confidence=intel.confidence,
        severity=sev,
        category=None,
        reference_url=intel.raw_reference,
        error_status=error_status,
        result_state=result_state(intel.status),
    )


def configured_providers() -> list[str]:
    """Providers that are both enabled and have a key; only these count as checked."""
    providers = []
    if settings.enable_virustotal and (settings.virustotal_api_key or "").strip():
        providers.append("virustotal")
    if settings.enable_urlhaus and (settings.urlhaus_auth_key or "").strip():
        providers.append("urlhaus")
    if settings.enable_abuseipdb and (settings.abuseipdb_api_key or "").strip():
        providers.append("abuseipdb")
    return providers + lookups.enabled_providers()


async def _virustotal_evidence(result) -> NormalizedTIEvidence | None:
    """
    VirusTotal hash verdict as TI evidence (Phase A gap #9). It used to be appended
    as a local finding; it is external evidence and never changes result.verdict.
    """
    vt_intel = await lookup_file_hash(result.sha256_hash)
    status = vt_intel.status
    if status in ("unconfigured", "invalid_hash"):
        return None

    error_status = status if status in _UNAVAILABLE else None
    if status in ("unauthorized", "forbidden"):
        result.verification_limitations.append("VT_UNAVAILABLE_AUTH")
    elif error_status:
        result.verification_limitations.append(f"VT_UNAVAILABLE_{status.upper()}")

    if error_status:
        rep, sev = "unknown", "informational"
    elif status == "malicious":
        rep, sev = "malicious", "critical"
        if result.verdict in ("clean_verified", "clean_with_limitations"):
            result.verification_limitations.append("CONFLICT_VT_MALICIOUS")
    elif status == "suspicious":
        rep, sev = "suspicious", "high"
    elif status == "clean":
        rep, sev = "benign", "informational"
    else:  # not_found and anything unexpected: the hash is unknown, not clean
        rep, sev = "unknown", "informational"

    return NormalizedTIEvidence(
        provider="virustotal",
        indicator_type="sha256",
        indicator=result.sha256_hash,
        reputation=rep,
        confidence=vt_intel.confidence,
        severity=sev,
        category=vt_intel.tags[0] if vt_intel.tags else None,
        reference_url=vt_intel.raw_reference,
        error_status=error_status,
        result_state=result_state(status),
    )


async def _fused_report(result, file_path: str, evidence: list[NormalizedTIEvidence]) -> TIFusionReport:
    indicators = await run_in_threadpool(extract_indicators, file_path)

    for url in indicators.urls:
        intel = await lookup_url(url)
        if intel.status != "unconfigured":
            evidence.append(_url_evidence(url, intel))

    for ip in indicators.ips:
        intel = await lookup_ip(ip)
        if intel.status not in ("unconfigured", "invalid_ip"):
            evidence.append(_ip_evidence(ip, intel))

    # Approved lookup-only providers (each returns None when disabled).
    for lookup in (lookups.malwarebazaar_hash, lookups.threatfox_hash, lookups.circl_hash,
                   lookups.yaraify_hash):
        ev = await lookup(result.sha256_hash)
        if ev is not None:
            evidence.append(ev)
    for url in indicators.urls:
        ev = await lookups.threatfox_url(url)
        if ev is not None:
            evidence.append(ev)
    for url in indicators.urls[: lookups._URLSCAN_MAX_URLS]:
        ev = await lookups.urlscan_url(url)
        if ev is not None:
            evidence.append(ev)

    report = fuse_reports(evidence, configured_providers())
    conflict = evaluate_local_verdict_conflict(result.verdict, report)
    if conflict:
        result.verification_limitations.append(conflict)
    result.verification_limitations.extend(report.limitations)
    return report


async def enrich_scan_result(result, file_path: str) -> TIFusionReport | None:
    """
    Add threat-intel evidence to a ScanEngineResult in place and return the fusion
    report (None if fusion failed). Provider failures degrade to limitations; this
    function does not raise for provider or network errors.
    """
    evidence: list[NormalizedTIEvidence] = []
    try:
        vt_evidence = await _virustotal_evidence(result)
        if vt_evidence:
            evidence.append(vt_evidence)
    except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
        logger.warning("Threat intel integration failed: %s", exc)
        result.verification_limitations.append("THREAT_INTEL_FAILURE")

    try:
        return await _fused_report(result, file_path, evidence)
    except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
        logger.warning("TI fusion failed: %s", exc)
        result.verification_limitations.append("THREAT_INTEL_FUSION_FAILURE")
        return None
