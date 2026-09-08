"""
Aegis Node - AbuseIPDB API Threat Intelligence Client.
"""
import logging
import httpx
import time
import ipaddress
from typing import Dict, Tuple

from backend.schemas import ThreatIntelResult
from backend.config import settings

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

# Simple in-memory TTL cache to avoid repeating identical queries
# Key: "abuseipdb:" + normalized_ip, Value: (timestamp_seconds, ThreatIntelResult)
_CACHE: Dict[str, Tuple[float, ThreatIntelResult]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour

def _is_public_ip(ip_str: str) -> bool:
    """Validates if a string is a valid, publicly routable IPv4/IPv6 address."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.is_global
    except ValueError:
        return False

def _normalize_ip(ip_str: str) -> str:
    """Returns the normalized string representation of the IP."""
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        return ip_str.strip()

async def lookup_ip(raw_ip: str) -> ThreatIntelResult:
    """
    Looks up an IP address in AbuseIPDB.
    Validates and rejects non-public/private IPs locally.
    """
    normalized_ip = _normalize_ip(raw_ip)
    cache_key = f"abuseipdb:{normalized_ip}"

    base_res = ThreatIntelResult(
        provider="abuseipdb",
        indicator_type="ip",
        indicator=raw_ip,
        status="error",
        source="AbuseIPDB",
        raw_reference=None
    )

    if not raw_ip:
        base_res.status = "invalid_ip"
        base_res.error_message = "Empty IP provided"
        return base_res

    if not _is_public_ip(raw_ip):
        base_res.status = "invalid_ip"
        base_res.error_message = "Non-public or invalid IP address"
        return base_res

    if not getattr(settings, 'enable_abuseipdb', False):
        base_res.status = "unconfigured"
        return base_res

    api_key = (getattr(settings, 'abuseipdb_api_key', None) or "").strip()
    if not api_key:
        base_res.status = "unconfigured"
        return base_res

    # Check cache
    now = time.time()
    if cache_key in _CACHE:
        cached_time, cached_result = _CACHE[cache_key]
        if now - cached_time < CACHE_TTL_SECONDS:
            return cached_result

    # Eviction
    if len(_CACHE) > 1000:
        sorted_keys = sorted(_CACHE.keys(), key=lambda k: _CACHE[k][0])
        for k in sorted_keys[:500]:
            _CACHE.pop(k, None)

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }

    params = {
        "ipAddress": normalized_ip,
        "maxAgeInDays": "90"
    }

    timeout = float(getattr(settings, 'abuseipdb_timeout_seconds', 5.0))

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(_ABUSEIPDB_URL, headers=headers, params=params)

            if resp.status_code == 401:
                base_res.status = "unauthorized"
                base_res.error_message = f"AbuseIPDB auth error {resp.status_code}"
                return base_res

            if resp.status_code == 403:
                base_res.status = "forbidden"
                base_res.error_message = f"AbuseIPDB forbidden {resp.status_code}"
                return base_res

            if resp.status_code == 429:
                base_res.status = "rate_limited"
                base_res.error_message = "HTTP 429 Rate Limited"
                return base_res

            if resp.status_code >= 500:
                base_res.status = "provider_error"
                base_res.error_message = f"HTTP {resp.status_code} Provider Error"
                return base_res

            resp.raise_for_status()
            payload = resp.json()
            data = payload.get("data", {})

            score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)

            if score == 0:
                base_res.status = "clean"
            elif score >= 80:
                base_res.status = "malicious"
                base_res.malicious_count = total_reports
            else:
                base_res.status = "suspicious"
                base_res.suspicious_count = total_reports

            base_res.confidence = f"score:{score}"

            _CACHE[cache_key] = (now, base_res)
            return base_res

    except httpx.TimeoutException:
        base_res.status = "timeout"
        base_res.error_message = "Request timed out"
        return base_res
    except Exception as exc:
        base_res.status = "provider_error"
        base_res.error_message = str(exc)
        return base_res
