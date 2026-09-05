"""
Aegis Node — URLhaus API Reputation Client.
"""
import logging
import httpx
from schemas import ThreatIntelResult
from config import settings

logger = logging.getLogger(__name__)

_URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

async def lookup_url(url: str) -> ThreatIntelResult:
    base_res = ThreatIntelResult(
        provider="urlhaus",
        indicator_type="url",
        indicator=url,
        status="error",
        source="URLhaus"
    )
    if not url:
        return base_res

    if not getattr(settings, 'enable_urlhaus', False):
        base_res.status = "unconfigured"
        return base_res

    timeout = 10.0

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(_URLHAUS_API_URL, data={"url": url})
            if resp.status_code != 200:
                base_res.status = "unavailable"
                return base_res
                
            payload = resp.json()
            query_status = payload.get("query_status")
            
            if query_status == "ok":
                base_res.status = "malicious"
                base_res.tags = payload.get("tags", [])
                base_res.first_seen = payload.get("date_added")
            elif query_status == "no_results":
                base_res.status = "not_found"
            else:
                base_res.status = "error"
            return base_res

    except Exception as exc:
        logger.warning(f"URLhaus lookup failed for URL {url}: {exc}")
        base_res.status = "error"
        return base_res
