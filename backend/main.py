"""
Aegis Node — Backend Entry Point
FastAPI application with dataset scanning API, rate limiting, and rich health check.
"""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from config import settings
from database import create_all_tables
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from routers.analysis import router as analysis_router
from routers.datasets import router as datasets_router
from routers.history import router as history_router
from routers.remediation import router as remediation_router
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware


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
# Uses X-Forwarded-For when behind an Nginx reverse proxy so each real client
# IP is tracked independently, not the shared 127.0.0.1 proxy address.
def _get_client_ip(request: Request) -> str:
    """
    Extract the real client IP from X-Forwarded-For header (set by Nginx via
    `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`).
    Falls back to direct connection IP in local dev mode.
    """
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Header may contain a comma-separated list; first entry is the real client
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_get_client_ip, default_limits=["200/hour"])
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# ─── CORS ─────────────────────────────────────────────────────────────────────
# Allow all origins in production (Render/Railway assign dynamic subdomains).
# Restrict to specific domains if you need tighter security.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,   # Must be False when allow_origins=["*"]
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
@limiter.limit("30/minute")       # Health checks: generous but bounded
async def health(request: Request) -> dict:
    """Extended health probe — actively checks ClamAV and AI configuration."""
    import sys
    from pathlib import Path
    _ROOT = Path(__file__).parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    # ClamAV ping
    try:
        from scanner.clamd_client import ping as clamav_ping
        clamav_running = clamav_ping(host=settings.clamav_host, port=settings.clamav_port)
    except Exception:
        clamav_running = False
    # AI availability — check full fallback chain, not just primary provider
    # (Improvement 2: if primary has no key but a fallback does, still report true)
    try:
        from services.llm_service import _build_provider_chain, _get_provider_key
        chain = _build_provider_chain()
        ai_configured = any(
            (bool(_get_provider_key(p, is_fb)) or p == "ollama")
            for p, is_fb in chain if p != "none"
        )
    except Exception:
        # Fallback to simple primary check if service import fails
        ai_provider = settings.ai_provider
        ai_configured = (
            (ai_provider == "gemini" and bool(settings.gemini_api_key))
            or (ai_provider == "groq" and bool(settings.groq_api_key))
            or (ai_provider == "ollama")
        )
    return {
        "status": "ok",
        "version": "0.1.0",
        "clamav_running": clamav_running,
        "ai_configured": ai_configured,
        "ai_provider": settings.ai_provider,
        "ai_fallback_chain": settings.ai_fallback_chain or "none",
        "max_file_size_mb": settings.max_upload_size_mb,
        "supported_formats": ["csv", "json", "jsonl", "parquet", "xlsx", "txt"],
    }


# ─── Frontend Static Files (React SPA) ───────────────────────────────────────
# Serve the Vite-built React app from the /static directory.
# In development (no /static dir), this block is skipped gracefully.
_STATIC_DIR = Path(__file__).parent / "static"
if _STATIC_DIR.exists():
    # Mount assets under /assets (Vite output structure)
    app.mount("/assets", StaticFiles(directory=str(_STATIC_DIR / "assets")), name="assets")

    @app.get("/", include_in_schema=False)
    async def serve_root():
        """Serve React index.html at root."""
        return FileResponse(str(_STATIC_DIR / "index.html"))

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa(full_path: str):
        """
        SPA catch-all: serve index.html for any path not matched by API routers.
        This enables React client-side navigation (tab switching, etc.).
        """
        # Don't intercept API or system routes
        if full_path.startswith(("api/", "health", "docs", "openapi", "redoc")):
            from fastapi import HTTPException
            raise HTTPException(status_code=404)
        return FileResponse(str(_STATIC_DIR / "index.html"))
else:
    # Development mode — just return API info at root
    @app.get("/", tags=["system"])
    async def root() -> dict:
        return {"message": "Aegis Node API — see /docs for usage. Frontend not bundled in dev mode."}
