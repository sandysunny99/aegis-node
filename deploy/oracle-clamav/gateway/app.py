"""
Aegis scan gateway — the only service the Oracle VM exposes (behind Caddy's HTTPS).

Render's Aegis backend calls it with a bearer token; it forwards exactly two
clamav-rest routes over the private Docker network and nothing else:

  GET  /healthz          no auth; {"status": "ok"} only, no versions or secrets
  GET  /api/v1/version   auth; real ClamAV version and signature date
  POST /api/v1/scan      auth; multipart field FILES, size-limited, rate-limited

It is not a proxy: no other path, host or URL can be reached through it. It never
logs the token, file names or file contents.
"""

import hmac
import logging
import os
import threading
import time
from collections import deque

import httpx
from fastapi import FastAPI, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse

logger = logging.getLogger("aegis.scan_gateway")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

_CHUNK = 1024 * 1024


class GatewaySettings:
    def __init__(self, env: dict[str, str] | None = None):
        env = os.environ if env is None else env
        self.token = env.get("SCAN_GATEWAY_TOKEN", "")
        if len(self.token) < 32:
            raise RuntimeError("SCAN_GATEWAY_TOKEN must be set and at least 32 characters long")
        self.upstream = env.get("CLAMAV_REST_URL", "http://clamav-rest:3000").rstrip("/")
        self.max_upload_bytes = int(env.get("MAX_UPLOAD_MB", "50")) * 1024 * 1024
        self.rate_per_minute = int(env.get("RATE_LIMIT_PER_MINUTE", "30"))
        self.max_concurrency = int(env.get("MAX_CONCURRENT_SCANS", "2"))
        self.upstream_timeout = float(env.get("UPSTREAM_TIMEOUT_SECONDS", "90"))


class _RateLimiter:
    """Sliding one-minute window per client plus a global concurrency cap."""

    def __init__(self, per_minute: int, concurrency: int):
        self.per_minute = per_minute
        self._hits: dict[str, deque] = {}
        self._lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(concurrency)

    def allow(self, client: str) -> bool:
        now = time.monotonic()
        with self._lock:
            window = self._hits.setdefault(client, deque())
            while window and now - window[0] > 60:
                window.popleft()
            if len(window) >= self.per_minute:
                return False
            window.append(now)
            return True


def create_app(settings: GatewaySettings | None = None,
               transport: httpx.BaseTransport | None = None) -> FastAPI:
    cfg = settings or GatewaySettings()
    limiter = _RateLimiter(cfg.rate_per_minute, cfg.max_concurrency)
    app = FastAPI(title="Aegis scan gateway", docs_url=None, redoc_url=None, openapi_url=None)

    def client_id(request: Request) -> str:
        # Caddy is the only peer and sets X-Forwarded-For; fall back to the socket peer.
        forwarded = request.headers.get("x-forwarded-for", "")
        return forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")

    def authorize(request: Request) -> None:
        header = request.headers.get("authorization", "")
        supplied = header[7:] if header.lower().startswith("bearer ") else ""
        if not hmac.compare_digest(supplied.encode(), cfg.token.encode()):
            raise HTTPException(status_code=401, detail="unauthorized")
        if not limiter.allow(client_id(request)):
            raise HTTPException(status_code=429, detail="rate limit exceeded")

    def upstream_client(timeout: float) -> httpx.Client:
        return httpx.Client(timeout=timeout, transport=transport)

    @app.middleware("http")
    async def access_log(request: Request, call_next):
        start = time.monotonic()
        response = await call_next(request)
        logger.info("%s %s -> %s in %dms", request.method, request.url.path,
                    response.status_code, (time.monotonic() - start) * 1000)
        return response

    @app.get("/healthz")
    def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/api/v1/version")
    def version(request: Request):
        authorize(request)
        try:
            with upstream_client(10.0) as client:
                resp = client.get(f"{cfg.upstream}/api/v1/version")
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="clamav unavailable") from None
        return JSONResponse(status_code=resp.status_code, content=_json_or_error(resp))

    @app.post("/api/v1/scan")
    def scan(request: Request, FILES: UploadFile):  # noqa: N803 — clamav-rest's field name
        authorize(request)
        declared = int(request.headers.get("content-length") or 0)
        if declared > cfg.max_upload_bytes + 64 * 1024:
            raise HTTPException(status_code=413, detail="file too large")
        size = 0
        FILES.file.seek(0)
        while chunk := FILES.file.read(_CHUNK):
            size += len(chunk)
            if size > cfg.max_upload_bytes:
                raise HTTPException(status_code=413, detail="file too large")
        FILES.file.seek(0)

        if not limiter.slots.acquire(blocking=False):
            raise HTTPException(status_code=503, detail="scanner busy, retry later")
        try:
            with upstream_client(cfg.upstream_timeout) as client:
                resp = client.post(
                    f"{cfg.upstream}/api/v1/scan",
                    files={"FILES": ("upload.bin", FILES.file, "application/octet-stream")},
                )
        except httpx.HTTPError:
            raise HTTPException(status_code=503, detail="clamav unavailable") from None
        finally:
            limiter.slots.release()
        return JSONResponse(status_code=resp.status_code, content=_json_or_error(resp))

    return app


def _json_or_error(resp: httpx.Response) -> dict:
    try:
        payload = resp.json()
    except ValueError:
        return {"success": False, "message": "invalid response from clamav-rest"}
    return payload if isinstance(payload, dict) else {"success": False, "message": "invalid response"}


if os.environ.get("SCAN_GATEWAY_TOKEN"):
    app = create_app()
