"""
Aegis Node - URLhaus API Threat Intelligence Client.
"""
import logging
import httpx
import time
from typing import Dict, Tuple
from urllib.parse import urlparse

from schemas import ThreatIntelResult
from config import settings

logger = logging.getLogger(__name__)

_URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

# Simple in-memory TTL cache to avoid repeating identical queries
# Key: "urlhaus:" + normalized_url, Value: (timestamp_seconds, ThreatIntelResult)
_CACHE: Dict[str, Tuple[float, ThreatIntelResult]] = {}
CACHE_TTL_SECONDS = 3600  # 1 hour

def _normalize_url(raw_url: str) -> str:
    """Safely normalizes a URL for looking up without resolving/fetching it."""
    url = raw_url.strip()
    try:
        parsed = urlparse(url)
        # Reconstruct standard format without fragments
        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        netloc = parsed.netloc.lower()
        path = parsed.path if parsed.path else "/"
        query = f"?{parsed.query}" if parsed.query else ""
        return f"{scheme}://{netloc}{path}{query}"
    except Exception:
        return url

async def lookup_url(raw_url: str) -> ThreatIntelResult:
    """
    Looks up a URL in URLhaus.
    CRITICAL: This function must NEVER connect to the raw_url itself.
    It must ONLY connect to the URLhaus API.
    """
    normalized_url = _normalize_url(raw_url)
    cache_key = f"urlhaus:{normalized_url}"

    base_res = ThreatIntelResult(
        provider="urlhaus",
        indicator_type="url",
        indicator=raw_url,
        status="error",
        source="URLhaus",
        raw_reference=None
    )

    if not raw_url:
        base_res.status = "invalid_url"
        base_res.error_message = "Empty URL provided"
        return base_res

    if not getattr(settings, 'enable_urlhaus', False):
        base_res.status = "unconfigured"
        return base_res

    api_key = (getattr(settings, 'urlhaus_auth_key', None) or "").strip()
    if not api_key:
        base_res.status = "unconfigured"
        return base_res

    # Check cache
    now = time.time()
    if cache_key in _CACHE:
        cached_time, cached_result = _CACHE[cache_key]
        if now - cached_time < CACHE_TTL_SECONDS:
            logger.info("URLhaus cache hit for URL...")
            return cached_result

    # Simple size-based eviction
    if len(_CACHE) > 1000:
        sorted_keys = sorted(_CACHE.keys(), key=lambda k: _CACHE[k][0])
        for k in sorted_keys[:500]:
            _CACHE.pop(k, None)

    headers = {
        "Auth-Key": api_key,
        "Accept": "application/json",
    }

    data = {
        "url": normalized_url
    }

    timeout = float(getattr(settings, 'urlhaus_timeout_seconds', 5.0))

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            # ONLY connect to URLhaus, never to the extracted URL.
            resp = await client.post(_URLHAUS_API_URL, headers=headers, data=data)

            if resp.status_code == 401:
                base_res.status = "unauthorized"
                base_res.error_message = f"URLhaus auth error {resp.status_code}"
                return base_res

            if resp.status_code == 403:
                base_res.status = "forbidden"
                base_res.error_message = f"URLhaus forbidden {resp.status_code}"
                return base_res

            if resp.status_code == 429:
                logger.warning("URLhaus API rate limit hit")
                base_res.status = "rate_limited"
                base_res.error_message = "HTTP 429 Rate Limited"
                return base_res

            if resp.status_code == 404:
                base_res.status = "not_found"
                _CACHE[cache_key] = (now, base_res)
                return base_res

            resp.raise_for_status()
            payload = resp.json()

            query_status = payload.get("query_status", "")

            if query_status in ("no_results", "invalid_url"):
                base_res.status = "not_found" if query_status == "no_results" else "invalid_url"
                base_res.error_message = payload.get("message", "No results found")
                # Cache negative results too
                _CACHE[cache_key] = (now, base_res)
                return base_res

            if query_status == "ok":
                url_status = payload.get("url_status", "unknown")
                tags = payload.get("tags", [])
                threat = payload.get("threat", "unknown")

                base_res.malicious_count = 1 if url_status in ("online", "offline") and threat != "unknown" else 0
                base_res.status = "malicious" if base_res.malicious_count > 0 else "clean"
                base_res.tags = tags if tags else []
                base_res.raw_reference = payload.get("urlhaus_reference")

                _CACHE[cache_key] = (now, base_res)
                return base_res

            # Any other status
            base_res.status = "provider_error"
            base_res.error_message = f"Unexpected query_status: {query_status}"
            return base_res

    except httpx.TimeoutException:
        logger.warning("URLhaus lookup timeout")
        base_res.status = "timeout"
        base_res.error_message = "Request timed out"
        return base_res
    except Exception as exc:
        logger.warning("URLhaus lookup failed: %s", exc)
        base_res.status = "provider_error"
        base_res.error_message = str(exc)
        return base_res
