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
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from limiter import limiter
from routers.analysis import router as analysis_router
from routers.datasets import router as datasets_router
from routers.history import router as history_router
from routers.remediation import router as remediation_router
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from utils.auth import require_api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on startup."""
    create_all_tables()
    yield


app = FastAPI(
    title="Aegis Node API",
    description="AI-Assisted Dataset Threat Detection and Remediation",
    version="0.1.0",
    lifespan=lifespan,
)

# ─── Rate Limiting ────────────────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# ─── CORS ─────────────────────────────────────────────────────────────────────
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
    # ClamAV ping
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
        or (ai_provider == "ollama")
    )

    return {
        "status": "ok",
        "version": "0.1.0",
        "clamav_running": clamav_running,
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
