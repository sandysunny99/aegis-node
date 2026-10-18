"""
Aegis Node — lookup-only threat-intel adapters approved on 18 Oct 2026:
MalwareBazaar (hash), ThreatFox (hash, URL) and CIRCL hashlookup (known-good hash).

Rules (docs/THREAT_INTELLIGENCE_PROVIDER_AUDIT.md, docs/THREAT_INTEL_API_CONTRACT.md):
- Off by default; each has its own flag. abuse.ch providers need an Auth-Key.
- Only a SHA-256 or an already-extracted URL is sent, to fixed official endpoints.
  No sample download (MalwareBazaar get_file), no upload, no submission.
- Every outcome is an explicit result_state. NO_MATCH is not "safe"; a failure is
  never a no-match; failures are not cached, answers are (1 hour).
- Responses larger than 1 MB, non-JSON or of an unexpected shape are INVALID_RESPONSE.
- A CIRCL match is "known_good": an annotation that fusion ignores, so it can never
  downgrade or cancel a local finding.
"""

import asyncio
import json
import logging
import re
import time

import httpx
from config import settings
from schemas import NormalizedTIEvidence

logger = logging.getLogger(__name__)

_MB_URL = "https://mb-api.abuse.ch/api/v1/"
_TF_URL = "https://threatfox-api.abuse.ch/api/v1/"
_CIRCL_URL = "https://hashlookup.circl.lu/lookup/sha256/"
_MAX_BYTES = 1024 * 1024
_CACHE_TTL = 3600.0
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

_TRANSPORT: httpx.AsyncBaseTransport | None = None  # tests inject httpx.MockTransport
_cache: dict[tuple[str, str, str], tuple[float, NormalizedTIEvidence]] = {}
_locks: dict[tuple[str, str, str], asyncio.Lock] = {}


def clear_cache() -> None:
    _cache.clear()
    _locks.clear()


def _abusech_key() -> str:
    return (settings.abusech_auth_key or settings.urlhaus_auth_key or "").strip()


def enabled_providers() -> list[str]:
    providers = []
    if settings.enable_malwarebazaar and _abusech_key():
        providers.append("malwarebazaar")
    if settings.enable_threatfox and _abusech_key():
        providers.append("threatfox")
    if settings.enable_circl_hashlookup:
        providers.append("circl_hashlookup")
    return providers


async def _request(method: str, url: str, **kwargs) -> tuple[str, dict | None]:
    """One bounded request: (state, payload) where state is OK, NOT_FOUND or a failure state."""
    timeout = httpx.Timeout(float(settings.threat_intel_timeout_seconds), connect=5.0)
    try:
        async with httpx.AsyncClient(timeout=timeout, transport=_TRANSPORT, follow_redirects=False) as client:
            async with client.stream(method, url, **kwargs) as resp:
                if resp.status_code in (401, 403):
                    return "UNAUTHORIZED", None
                if resp.status_code == 429:
                    return "RATE_LIMITED", None
                if resp.status_code == 404:
                    return "NOT_FOUND", None
                if resp.status_code >= 500:
                    return "UNAVAILABLE", None
                if resp.status_code != 200:
                    return "INVALID_RESPONSE", None
                body = b""
                async for chunk in resp.aiter_bytes():
                    body += chunk
                    if len(body) > _MAX_BYTES:
                        return "INVALID_RESPONSE", None
    except httpx.TimeoutException:
        return "TIMEOUT", None
    except httpx.HTTPError:
        return "UNAVAILABLE", None
    try:
        payload = json.loads(body)
    except ValueError:
        return "INVALID_RESPONSE", None
    return ("OK", payload) if isinstance(payload, dict) else ("INVALID_RESPONSE", None)


def _evidence(provider: str, kind: str, indicator: str, state: str, *, category=None,
              reference=None, confidence=None, reputation=None) -> NormalizedTIEvidence:
    failed = state not in ("MATCH", "NO_MATCH")
    if reputation is None:
        reputation = "malicious" if state == "MATCH" else "unknown"
    return NormalizedTIEvidence(
        provider=provider,
        indicator_type=kind,
        indicator=indicator,
        reputation=reputation,
        severity="critical" if reputation == "malicious" else "informational",
        category=category,
        reference_url=reference,
        confidence=confidence,
        error_status=state.lower() if failed else None,
        result_state=state,
    )


async def _cached(provider: str, kind: str, indicator: str, fetch) -> NormalizedTIEvidence:
    key = (provider, kind, indicator)
    lock = _locks.setdefault(key, asyncio.Lock())
    async with lock:  # concurrent scans of the same indicator share one request
        hit = _cache.get(key)
        if hit and time.monotonic() - hit[0] < _CACHE_TTL:
            return hit[1]
        ev = await fetch()
        if ev.result_state in ("MATCH", "NO_MATCH"):
            _cache[key] = (time.monotonic(), ev)
        return ev


def _abusech_result(provider: str, kind: str, indicator: str, state: str, payload: dict | None,
                    no_match_statuses: tuple[str, ...], category_keys: tuple[str, ...],
                    reference: str | None) -> NormalizedTIEvidence:
    if state != "OK":
        return _evidence(provider, kind, indicator, "NO_MATCH" if state == "NOT_FOUND" else state)
    status = str(payload.get("query_status", ""))
    if status in no_match_statuses:
        return _evidence(provider, kind, indicator, "NO_MATCH")
    if "auth" in status.lower():
        return _evidence(provider, kind, indicator, "UNAUTHORIZED")
    data = payload.get("data")
    if status != "ok" or not isinstance(data, list) or not data or not isinstance(data[0], dict):
        return _evidence(provider, kind, indicator, "INVALID_RESPONSE")
    first = data[0]
    category = next((str(first[k])[:80] for k in category_keys if first.get(k)), None)
    if category is None and isinstance(first.get("tags"), list) and first["tags"]:
        category = str(first["tags"][0])[:80]
    return _evidence(provider, kind, indicator, "MATCH", category=category, reference=reference)


async def malwarebazaar_hash(sha256: str) -> NormalizedTIEvidence | None:
    sha256 = (sha256 or "").strip().lower()
    if "malwarebazaar" not in enabled_providers() or not _SHA256_RE.fullmatch(sha256):
        return None

    async def fetch():
        state, payload = await _request("POST", _MB_URL, headers={"Auth-Key": _abusech_key()},
                                        data={"query": "get_info", "hash": sha256})
        return _abusech_result("malwarebazaar", "sha256", sha256, state, payload,
                               ("hash_not_found", "no_results"), ("signature",),
                               f"https://bazaar.abuse.ch/sample/{sha256}/")
    return await _cached("malwarebazaar", "sha256", sha256, fetch)


async def threatfox_hash(sha256: str) -> NormalizedTIEvidence | None:
    sha256 = (sha256 or "").strip().lower()
    if "threatfox" not in enabled_providers() or not _SHA256_RE.fullmatch(sha256):
        return None

    async def fetch():
        state, payload = await _request("POST", _TF_URL, headers={"Auth-Key": _abusech_key()},
                                        json={"query": "search_hash", "hash": sha256})
        return _abusech_result("threatfox", "sha256", sha256, state, payload,
                               ("no_result", "hash_not_found"), ("malware_printable", "threat_type"), None)
    return await _cached("threatfox", "sha256", sha256, fetch)


async def threatfox_url(url: str) -> NormalizedTIEvidence | None:
    url = (url or "").strip()
    if "threatfox" not in enabled_providers() or not url.lower().startswith(("http://", "https://")):
        return None

    async def fetch():
        state, payload = await _request("POST", _TF_URL, headers={"Auth-Key": _abusech_key()},
                                        json={"query": "search_ioc", "search_term": url, "exact_match": True})
        return _abusech_result("threatfox", "url", url, state, payload,
                               ("no_result",), ("malware_printable", "threat_type"), None)
    return await _cached("threatfox", "url", url, fetch)


async def circl_hash(sha256: str) -> NormalizedTIEvidence | None:
    sha256 = (sha256 or "").strip().lower()
    if "circl_hashlookup" not in enabled_providers() or not _SHA256_RE.fullmatch(sha256):
        return None

    async def fetch():
        state, payload = await _request("GET", f"{_CIRCL_URL}{sha256}", headers={"Accept": "application/json"})
        if state == "NOT_FOUND":
            return _evidence("circl_hashlookup", "sha256", sha256, "NO_MATCH")
        if state != "OK":
            return _evidence("circl_hashlookup", "sha256", sha256, state)
        trust = payload.get("hashlookup:trust")
        source = payload.get("source") or payload.get("db")
        return _evidence("circl_hashlookup", "sha256", sha256, "MATCH", reputation="known_good",
                         category=f"known_file:{str(source)[:40]}" if source else "known_file",
                         confidence=f"trust:{trust}" if trust is not None else None)
    return await _cached("circl_hashlookup", "sha256", sha256, fetch)
