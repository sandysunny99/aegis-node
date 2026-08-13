"""
Aegis Node — Shared Rate Limiter
Single SlowAPI Limiter instance shared across main app and all router modules.
"""

from config import settings
from fastapi import Request
from slowapi import Limiter


def _get_client_ip(request: Request) -> str:
    """
    Extract the client IP for rate limiting.
    Only respects X-Forwarded-For if the direct connecting host is in trusted_proxies.
    Prevents IP spoofing when exposed directly without a trusted proxy.
    """
    direct_host = request.client.host if request.client else "unknown"

    if direct_host in settings.trusted_proxies or "*" in settings.trusted_proxies:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return direct_host


# Singleton shared Limiter instance used across main.py and all API routers
limiter = Limiter(key_func=_get_client_ip, default_limits=["200/hour"])
