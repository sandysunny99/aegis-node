"""
Aegis Node — Shared Rate Limiter
Single SlowAPI Limiter instance shared across main app and all router modules.
"""

from config import settings
from fastapi import Request
from slowapi import Limiter


def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP for rate limiting and Turnstile `remoteip`.
    Proxy headers (CF-Connecting-IP, then X-Forwarded-For) are honoured only when the
    direct connecting host is in trusted_proxies (exact IPs or CIDR ranges, e.g.
    '10.0.0.0/8'); otherwise any client could spoof them (A-005, A-015, S6).
    Wildcard '*' is intentionally NOT supported.
    """
    direct_host = request.client.host if request.client else "unknown"

    if settings.is_trusted_proxy(direct_host):
        cf_ip = request.headers.get("CF-Connecting-IP")
        if cf_ip and cf_ip.strip():
            return cf_ip.strip()
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

    return direct_host


# Backwards-compatible name used by older code/tests.
_get_client_ip = get_client_ip


# Singleton shared Limiter instance used across main.py and all API routers
limiter = Limiter(key_func=get_client_ip, default_limits=["200/hour"])


