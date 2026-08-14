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
    Only respects X-Forwarded-For if the direct connecting host is in trusted_proxies
    (supports exact IPs and CIDR ranges, e.g. '10.0.0.0/8').
    Wildcard '*' is intentionally NOT supported to prevent IP spoofing (A-005, A-015).
    """
    direct_host = request.client.host if request.client else "unknown"

    # Use CIDR-aware trusted proxy check — no wildcard support (A-005)
    if settings.is_trusted_proxy(direct_host):
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return direct_host


# Singleton shared Limiter instance used across main.py and all API routers
limiter = Limiter(key_func=_get_client_ip, default_limits=["200/hour"])

