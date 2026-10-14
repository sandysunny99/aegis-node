"""
Aegis Node — Threat-intelligence enrichment of a completed local scan.

Extracted from the scan endpoint (C5). Order of operations:
  1. VirusTotal hash lookup (only the SHA-256 leaves the server).
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

from fastapi.concurrency import run_in_threadpool
from schemas import NormalizedTIEvidence, TIFusionReport

from scanner.content_checker import ContentFinding
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
        rep, sev = "benign", "informational"
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
    )


async def _apply_virustotal(result) -> None:
    """Append the VirusTotal hash verdict as a finding; never changes result.verdict."""
    vt_intel = await lookup_file_hash(result.sha256_hash)
    severity = "low"
    if vt_intel.status == "malicious":
        severity = "critical"
        if result.verdict in ("clean_verified", "clean_with_limitations"):
            result.verification_limitations.append("CONFLICT_VT_MALICIOUS")
    elif vt_intel.status == "suspicious":
        severity = "high"
    elif vt_intel.status in ("timeout", "rate_limited", "provider_error"):
        result.verification_limitations.append(f"VT_UNAVAILABLE_{vt_intel.status.upper()}")

    result.content_findings.append(ContentFinding(
        rule_id=f"vt_{vt_intel.status}",
        severity=severity,
        category="threat_intel",
        description=(
            f"VirusTotal {vt_intel.status.upper()} (Confidence: {vt_intel.confidence or 'N/A'})"
            f" - {vt_intel.error_message or 'No errors'}"
        ),
        location="virustotal",
        sample=vt_intel.raw_reference or "",
    ))


async def _fused_report(result, file_path: str) -> TIFusionReport:
    indicators = await run_in_threadpool(extract_indicators, file_path)
    evidence: list[NormalizedTIEvidence] = []

    for url in indicators.urls:
        intel = await lookup_url(url)
        if intel.status != "unconfigured":
            evidence.append(_url_evidence(url, intel))

    for ip in indicators.ips:
        intel = await lookup_ip(ip)
        if intel.status not in ("unconfigured", "invalid_ip"):
            evidence.append(_ip_evidence(ip, intel))

    report = fuse_reports(evidence, ["urlhaus", "abuseipdb"])
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
    try:
        await _apply_virustotal(result)
    except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
        logger.warning("Threat intel integration failed: %s", exc)
        result.verification_limitations.append("THREAT_INTEL_FAILURE")

    try:
        return await _fused_report(result, file_path)
    except Exception as exc:  # noqa: BLE001 — enrichment is best-effort
        logger.warning("TI fusion failed: %s", exc)
        result.verification_limitations.append("THREAT_INTEL_FUSION_FAILURE")
        return None
