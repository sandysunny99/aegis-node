"""
Aegis Node — VirusTotal API v3 Hash-First Reputation Client.
"""
import logging
import httpx
from schemas import ThreatIntelResult
from config import settings

logger = logging.getLogger(__name__)

_VT_FILES_URL = "https://www.virustotal.com/api/v3/files"

async def lookup_file_hash(sha256: str) -> ThreatIntelResult:
    sha256 = (sha256 or "").strip().lower()
    base_res = ThreatIntelResult(
        provider="virustotal",
        indicator_type="file_hash",
        indicator=sha256,
        status="error",
        source="VirusTotal"
    )
    if not sha256:
        base_res.tags = ["Empty SHA-256"]
        return base_res

    if not settings.enable_virustotal:
        base_res.status = "unconfigured"
        return base_res

    api_key = (settings.virustotal_api_key or "").strip()
    if not api_key:
        base_res.status = "unconfigured"
        return base_res

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }
    timeout = float(settings.virustotal_timeout_seconds or 10)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(f"{_VT_FILES_URL}/{sha256}", headers=headers)

            if resp.status_code == 404:
                base_res.status = "not_found"
                return base_res
            if resp.status_code == 429:
                logger.warning("VirusTotal public API rate limit hit")
                base_res.status = "rate_limited"
                return base_res

            resp.raise_for_status()
            payload = resp.json().get("data", {})
            attributes = payload.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            
            if malicious > 0 or suspicious > 0:
                base_res.status = "malicious" if malicious > 0 else "suspicious"
                base_res.confidence = f"{malicious}/{malicious+suspicious+stats.get('harmless', 0)}"
            else:
                base_res.status = "completed"
            
            threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label")
            if threat_label:
                base_res.tags.append(threat_label)
                
            return base_res

    except Exception as exc:
        logger.warning("VirusTotal lookup failed for hash %s: %s", sha256[:12], exc)
        base_res.status = "error"
        return base_res

