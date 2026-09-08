"""
Aegis Node - VirusTotal API v3 Hash-First Reputation Client.
"""
import logging
import httpx
import time
from typing import Dict, Tuple
from schemas import ThreatIntelResult
from config import settings

logger = logging.getLogger(__name__)

_VT_FILES_URL = "https://www.virustotal.com/api/v3/files"

# Simple in-memory TTL cache to avoid hitting VT limits (500/day, 4/min)
# Key: sha256, Value: (timestamp_seconds, ThreatIntelResult)
_CACHE: Dict[str, Tuple[float, ThreatIntelResult]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour

async def lookup_file_hash(sha256: str) -> ThreatIntelResult:
    sha256 = (sha256 or "").strip().lower()

    base_res = ThreatIntelResult(
        provider="virustotal",
        indicator_type="file_hash",
        indicator=sha256,
        status="error",
        source="VirusTotal",
        raw_reference=f"https://www.virustotal.com/gui/file/{sha256}" if sha256 else None
    )

    if not sha256 or len(sha256) != 64 or not all(c in "0123456789abcdef" for c in sha256):
        base_res.status = "invalid_hash"
        base_res.error_message = "Invalid SHA-256 format"
        return base_res

    if not settings.enable_virustotal:
        base_res.status = "unconfigured"
        return base_res

    api_key = (settings.virustotal_api_key or "").strip()
    if not api_key:
        base_res.status = "unconfigured"
        return base_res

    # Check cache
    now = time.time()
    if sha256 in _CACHE:
        cached_time, cached_result = _CACHE[sha256]
        if now - cached_time < CACHE_TTL_SECONDS:
            logger.info(f"VT cache hit for {sha256[:8]}...")
            return cached_result

    # Simple size-based eviction
    if len(_CACHE) > 1000:
        # Clear oldest half
        sorted_keys = sorted(_CACHE.keys(), key=lambda k: _CACHE[k][0])
        for k in sorted_keys[:500]:
            _CACHE.pop(k, None)

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    timeout = float(settings.virustotal_timeout_seconds or 5.0)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{_VT_FILES_URL}/{sha256}", headers=headers)

            if resp.status_code == 401 or resp.status_code == 403:
                base_res.status = "unauthorized"
                base_res.error_message = f"VirusTotal auth error {resp.status_code}"
                return base_res

            if resp.status_code == 404:
                base_res.status = "not_found"
                _CACHE[sha256] = (now, base_res)
                return base_res

            if resp.status_code == 429:
                logger.warning("VirusTotal public API rate limit hit")
                base_res.status = "rate_limited"
                base_res.error_message = "HTTP 429 Rate Limited"
                # Do not cache rate limits
                return base_res

            resp.raise_for_status()
            payload = resp.json().get("data", {})
            attributes = payload.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)

            base_res.malicious_count = malicious
            base_res.suspicious_count = suspicious
            base_res.harmless_count = harmless
            base_res.undetected_count = undetected

            base_res.confidence = f"{malicious}/{malicious+suspicious+harmless+undetected}"

            if malicious > 0:
                base_res.status = "malicious"
            elif suspicious > 0:
                base_res.status = "suspicious"
            else:
                base_res.status = "clean"

            threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label")
            if threat_label:
                base_res.tags.append(threat_label)

            # Cache the successful result
            _CACHE[sha256] = (now, base_res)
            return base_res

    except httpx.TimeoutException:
        logger.warning("VirusTotal lookup timeout for %s", sha256[:8])
        base_res.status = "timeout"
        base_res.error_message = "Request timed out"
        return base_res
    except Exception as exc:
        logger.warning("VirusTotal lookup failed for hash %s: %s", sha256[:8], exc)
        base_res.status = "provider_error"
        base_res.error_message = str(exc)
        return base_res

