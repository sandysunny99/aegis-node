"""
Aegis Node — Backend Entry Point
FastAPI application with dataset scanning API, rate limiting, and rich health check.
"""

import time
from contextlib import asynccontextmanager
from pathlib import Path

from config import settings
from database import create_all_tables
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from limiter import limiter
from routers.analysis import router as analysis_router
from routers.datasets import router as datasets_router
from routers.history import router as history_router
from routers.remediation import router as remediation_router
from routers.scans import router as scans_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from utils.auth import require_api_key
from version import APP_VERSION


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on startup."""
    create_all_tables()
    yield


# ─── Security Headers Middleware (A-006) ──────────────────────────────────────
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds essential HTTP security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://challenges.cloudflare.com; "
            "frame-src 'self' https://challenges.cloudflare.com; "
            # IBM Plex is served by Google Fonts (CSS from googleapis, files from gstatic)
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self' https://challenges.cloudflare.com"
        )
        return response


# ─── Production mode: disable OpenAPI docs (A-021) ───────────────────────────
_is_production = settings.app_env.lower() == "production"

app = FastAPI(
    title="Aegis Node API",
    description="AI-Assisted Dataset Threat Detection and Remediation",
    version=APP_VERSION,
    lifespan=lifespan,
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)

# ─── Rate Limiting ────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# ─── Security Headers (A-006) ───────────────────────────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)

# ─── Compression ─────────────────────────────────────────────────────────────
# The built UI ships ~360 KB of JavaScript; gzip brings the landing bundle to ~116 KB.
app.add_middleware(GZipMiddleware, minimum_size=1024)

# ─── CORS ────────────────────────────────────────────────────────────────────
# Configured via settings.allowed_origins ("*" in dev, domain list in production)
allow_all = "*" in settings.allowed_origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=not allow_all,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routers ──────────────────────────────────────────────────────────────────
app.include_router(datasets_router)
app.include_router(analysis_router)
app.include_router(history_router)
app.include_router(remediation_router)
app.include_router(scans_router)


# ─── Health Check ─────────────────────────────────────────────────────────────

_AV_STATUS_TTL_SECONDS = 300
_av_status_cache: dict = {"checked_at": None, "value": None}


def _probe_av() -> dict:
    """Actively query the AV provider (network call for ClamAV-REST / MetaDefender)."""
    from services.av_providers import get_av_provider

    provider = None
    try:
        provider = get_av_provider()
        available = provider.ping()
        return {
            "av_provider": provider.provider_name,
            "av_authority": provider.provider_authority,
            "av_available": available,
            "av_version": provider.get_version() if available else "Unavailable",
            "av_mock_mode": getattr(provider, "mock_mode", False),
        }
    except Exception:  # noqa: BLE001 — health must never raise
        return {
            "av_provider": getattr(provider, "provider_name", "unknown"),
            "av_authority": getattr(provider, "provider_authority", "unknown"),
            "av_available": False,
            "av_version": "Unavailable",
            "av_mock_mode": getattr(provider, "mock_mode", False),
        }


def _cached_av_status() -> dict:
    """
    S8: the public /health probe reuses an AV status at most _AV_STATUS_TTL_SECONDS old,
    so anonymous callers cannot turn it into MetaDefender/ClamAV traffic or quota burn.
    """
    now = time.monotonic()
    checked_at = _av_status_cache["checked_at"]
    if checked_at is None or now - checked_at > _AV_STATUS_TTL_SECONDS:
        _av_status_cache["value"] = _probe_av()
        _av_status_cache["checked_at"] = now
    return _av_status_cache["value"]


def _is_ai_provider_configured(provider: str) -> bool:
    p = provider.strip().lower()
    keys = {
        "gemini": settings.gemini_api_key,
        "groq": settings.groq_api_key,
        "xai": settings.xai_api_key,
        "cloudflare": settings.cloudflare_api_token,
        "nvidia": settings.nvidia_api_key,
        "huggingface": settings.hf_token,
    }
    if p in keys:
        return bool((keys[p] or "").strip())
    if p == "freellmapi":
        return bool(settings.freellmapi_enabled) and bool(settings.freellmapi_api_key.strip())
    return p == "ollama"


def _health_payload(av_status: dict) -> dict:
    ai_provider = settings.ai_provider.strip().lower()
    ai_fallback_chain = [
        p.strip().lower() for p in (settings.ai_fallback_chain or "").split(",") if p.strip()
    ]
    public_uploads = settings.allow_public_uploads is True
    turnstile_enabled = not public_uploads and bool(
        settings.cloudflare_turnstile_site_key.strip()
        and settings.cloudflare_turnstile_secret_key.strip()
    )
    return {
        "status": "ok",
        "version": APP_VERSION,
        **av_status,
        "ai_configured": _is_ai_provider_configured(ai_provider),
        "ai_provider": ai_provider,
        "ai_fallback_chain": ai_fallback_chain,
        "turnstile_enabled": turnstile_enabled,
        "turnstile_site_key": settings.cloudflare_turnstile_site_key if turnstile_enabled else "",
        "public_uploads": public_uploads,
        "max_file_size_mb": settings.max_upload_size_mb,
        "supported_formats": [ext.lstrip(".") for ext in sorted(settings.allowed_extensions)],
    }


@app.get("/health", tags=["system"])
@limiter.exempt
async def health(request: Request) -> dict:
    """
    Public health probe with UI status fields (AV status cached, see S8). Not rate
    limited: Render's health check comes from a few internal addresses and a 429
    here marks the instance unavailable.
    """
    return _health_payload(await run_in_threadpool(_cached_av_status))


@app.get("/health/detectors", tags=["system"])
@limiter.limit("30/minute")
async def health_detectors(request: Request) -> dict:
    """
    Active profile (lite | full) and, per detector, enabled / available / version /
    last error. Public; reuses the cached AV status (S8) and returns no secrets.
    """
    from services.detector_status import detector_report

    return detector_report(await run_in_threadpool(_cached_av_status))


@app.get("/health/diagnostics", tags=["system"])
@limiter.limit("30/minute")
async def health_diagnostics(
    request: Request,
    _auth: None = Depends(require_api_key),
) -> dict:
    """Protected extended health probe — actively re-checks the AV provider."""
    av_status = await run_in_threadpool(_probe_av)
    _av_status_cache.update(value=av_status, checked_at=time.monotonic())
    return _health_payload(av_status)


# ─── Frontend Static Files (React SPA) ───────────────────────────────────────
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    # index.html must be revalidated on every visit, or browsers keep showing an old UI after a
    # rebuild; the hashed /assets files can be cached as usual.
    _INDEX_HEADERS = {"Cache-Control": "no-cache"}

    # The page shell is static and cheap; the 200/hour default limit would lock out a user
    # who reloads the app often, so only the API routes are rate limited.
    @app.get("/", include_in_schema=False)
    @limiter.exempt
    async def serve_root():
        """Serve React index.html at root."""
        return FileResponse(str(_STATIC_DIR / "index.html"), headers=_INDEX_HEADERS)

    @app.get("/{full_path:path}", include_in_schema=False)
    @limiter.exempt
    async def serve_spa(full_path: str):
        """
        SPA catch-all: serve index.html for any path not matched by API routers.
        Enables React client-side navigation.
        """
        # Don't intercept API, documentation, or static asset routes (case-insensitive)
        if full_path.lower().startswith(("api/", "health", "docs", "openapi", "redoc", "assets")):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(str(_STATIC_DIR / "index.html"), headers=_INDEX_HEADERS)
else:
    # Development mode — just return API info at root
    @app.get("/", tags=["system"])
    async def root() -> dict:
        return {"message": "Aegis Node API — see /docs for usage. Frontend not bundled in dev mode."}
