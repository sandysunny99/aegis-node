"""
Aegis Node — AbuseIPDB API Reputation Client.
"""
import logging
import httpx
from schemas import ThreatIntelResult
from config import settings

logger = logging.getLogger(__name__)

_ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

async def lookup_ip(ip: str) -> ThreatIntelResult:
    base_res = ThreatIntelResult(
        provider="abuseipdb",
        indicator_type="ip",
        indicator=ip,
        status="error",
        source="AbuseIPDB"
    )
    if not ip:
        return base_res

    if not getattr(settings, 'enable_abuseipdb', False):
        base_res.status = "unconfigured"
        return base_res
        
    api_key = getattr(settings, 'abuseipdb_api_key', "").strip()
    if not api_key:
        base_res.status = "unconfigured"
        return base_res

    timeout = 10.0
    headers = {
        "Accept": "application/json",
        "Key": api_key
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(_ABUSEIPDB_URL, headers=headers, params={"ipAddress": ip, "maxAgeInDays": 90})
            if resp.status_code == 429:
                base_res.status = "rate_limited"
                return base_res
            if resp.status_code != 200:
                base_res.status = "unavailable"
                return base_res
                
            data = resp.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            
            if score > 0:
                base_res.status = "suspicious" if score < 80 else "malicious"
                base_res.confidence = f"score:{score}"
            else:
                base_res.status = "completed"
                
            return base_res

    except Exception as exc:
        logger.warning(f"AbuseIPDB lookup failed for IP {ip}: {exc}")
        base_res.status = "error"
        return base_res
