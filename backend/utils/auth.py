"""
Aegis Node — API Key Authentication Dependency.

Provides a lightweight optional API key guard for write endpoints.
If API_KEY is not set in config (empty string), the check is SKIPPED —
this allows zero-config local development.

When set, pass the key via:
    Header:  X-API-Key: <key>

Usage in routers:
    from utils.auth import require_api_key
    @router.post("/...", dependencies=[Depends(require_api_key)])
"""

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from config import settings

# FastAPI security scheme — reads X-API-Key header
_api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,          # Don't auto-raise; we handle the error ourselves
    description="Optional API key for write-endpoint protection. "
                "Leave unset in development (API_KEY not configured = open access).",
)


async def require_api_key(api_key: str | None = Security(_api_key_header)) -> None:
    """
    FastAPI dependency — validates X-API-Key header.

    Behaviour:
    - If settings.api_key is empty/unset → SKIP check (dev mode, open access).
    - If settings.api_key is set and header is missing → HTTP 401.
    - If settings.api_key is set and header is wrong → HTTP 401.
    - If settings.api_key is set and header matches → PASS.

    Uses secrets.compare_digest() for constant-time comparison (prevents
    timing oracle attacks where attackers measure response latency).
    """
    import secrets as _secrets

    configured_key: str = getattr(settings, "api_key", "")

    # Dev mode: no API key configured → open access (zero friction for local dev)
    if not configured_key:
        return

    # Key is configured — enforce it
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Include X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    if not _secrets.compare_digest(configured_key, api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )
