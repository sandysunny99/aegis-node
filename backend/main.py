"""
Aegis Node — Backend Entry Point
FastAPI application with dataset scanning API, rate limiting, and rich health check.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path
from config import settings
from database import create_all_tables
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from limiter import limiter
from routers.analysis import router as analysis_router
from routers.datasets import router as datasets_router
from routers.history import router as history_router
from routers.remediation import router as remediation_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from utils.auth import require_api_key


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
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'"
        )
        return response


# ─── Production mode: disable OpenAPI docs (A-021) ───────────────────────────
_is_production = settings.app_env.lower() == "production"

app = FastAPI(
    title="Aegis Node API",
    description="AI-Assisted Dataset Threat Detection and Remediation",
    version="0.1.0",
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


# ─── Health Check ─────────────────────────────────────────────────────────────

@app.get("/health", tags=["system"])
@limiter.limit("60/minute")
async def health(request: Request) -> dict:
    """Public health probe with UI status fields."""
    # ClamAV ping — test live socket unless in mock mode
    clamav_mock = bool(settings.clamav_mock_mode)
    if clamav_mock:
        clamav_running = False  # Explicitly false: running simulated/mock, not live daemon
    else:
        try:
            from scanner.clamd_client import ping as clamav_ping
            clamav_running = clamav_ping(host=settings.clamav_host, port=settings.clamav_port)
        except Exception:
            clamav_running = False

    # AI availability check
    ai_provider = settings.ai_provider.strip().lower()
    ai_configured = (
        (ai_provider == "gemini" and bool(settings.gemini_api_key.strip()))
        or (ai_provider == "groq" and bool(settings.groq_api_key.strip()))
        or (ai_provider == "xai" and bool(settings.xai_api_key.strip()))
        or (ai_provider == "ollama")
    )

    return {
        "status": "ok",
        "version": "0.1.0",
        "clamav_running": clamav_running,
        "clamav_mock": clamav_mock,
        "clamav_mock_mode": clamav_mock,  # A-019: explicit field for UI banner
        "ai_configured": ai_configured,
        "ai_provider": settings.ai_provider,
        "max_file_size_mb": settings.max_upload_size_mb,
        "supported_formats": [ext.lstrip(".") for ext in sorted(settings.allowed_extensions)],
    }



@app.get("/health/diagnostics", tags=["system"])
@limiter.limit("30/minute")
async def health_diagnostics(
    request: Request,
    _auth: None = Depends(require_api_key),
) -> dict:
    """Protected extended health probe — actively checks ClamAV and AI configuration."""
    return await health(request)


# ─── Frontend Static Files (React SPA) ───────────────────────────────────────
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_root():
        """Serve React index.html at root."""
        return FileResponse(str(_STATIC_DIR / "index.html"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        """
        SPA catch-all: serve index.html for any path not matched by API routers.
        Enables React client-side navigation.
        """
        # Don't intercept API, documentation, or static asset routes (case-insensitive)
        if full_path.lower().startswith(("api/", "health", "docs", "openapi", "redoc", "assets")):
            raise HTTPException(status_code=404, detail="Not found")
        return FileResponse(str(_STATIC_DIR / "index.html"))
else:
    # Development mode — just return API info at root
    @app.get("/", tags=["system"])
    async def root() -> dict:
        return {"message": "Aegis Node API — see /docs for usage. Frontend not bundled in dev mode."}
