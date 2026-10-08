"""
Aegis Node — ClamAV REST API Client.
Connects to a private benzino77/clamav-rest-api wrapper instance.
Falls back gracefully when daemon is unavailable.
"""

import logging
import threading
import time
from dataclasses import dataclass
import httpx

logger = logging.getLogger(__name__)

# Cache offline status for 5 seconds to avoid repeated socket timeouts when daemon is down
_OFFLINE_CACHE_TTL = 5.0
_last_failed_check: float = 0.0
_offline_lock = threading.Lock()


@dataclass
class ClamAVResult:
    available: bool          # False when API/daemon is not reachable
    infected: bool
    virus_name: str | None
    raw_response: str
    error: str | None


def _get_api_url() -> str:
    # Try to import from config, else default
    for _mod in ("config", "backend.config"):
        try:
            import importlib
            _cfg = importlib.import_module(_mod)
            if getattr(_cfg, "settings", None) and hasattr(_cfg.settings, "clamav_api_url"):
                url = _cfg.settings.clamav_api_url
                if url and not url.startswith("http"):
                    url = f"http://{url}"
                return url
            break
        except Exception:
            continue
    return "http://localhost:3000"


def _check_mock_mode() -> bool:
    for _mod in ("config", "backend.config"):
        try:
            import importlib
            _cfg = importlib.import_module(_mod)
            if getattr(_cfg, "settings", None) and getattr(_cfg.settings, "clamav_mock_mode", False):
                return True
            break
        except Exception:
            continue
    return False


def ping(api_url: str | None = None, host: str | None = None, port: int | None = None) -> bool:
    """Returns True if clamav-rest-api is reachable and reports healthy ClamAV."""
    # Note: host and port are accepted for backward compatibility with main.py/engine.py
    if _check_mock_mode():
        return True
    
    url = api_url or _get_api_url()
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{url.rstrip('/')}/api/v1/version")
            if resp.status_code == 200:
                data = resp.json()
                return data.get("success", False)
    except Exception:
        pass
    return False


def get_version(api_url: str | None = None) -> str:
    if _check_mock_mode():
        return "ClamAV (Mock)"
    
    url = api_url or _get_api_url()
    try:
        with httpx.Client(timeout=3.0) as client:
            resp = client.get(f"{url.rstrip('/')}/api/v1/version")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    return data.get("data", {}).get("clamav_version", "Unknown")
    except Exception:
        pass
    return "Unavailable"


def scan_file(path: str, api_url: str | None = None, host: str | None = None, port: int | None = None) -> ClamAVResult:
    """
    Primary entry point — send file to clamav-rest-api and return the scan result.
    If unreachable, returns ClamAVResult(available=False, infected=False).
    """
    if _check_mock_mode():
        return ClamAVResult(available=True, infected=False, virus_name=None, raw_response="{\"success\":true,\"data\":{\"result\":[{\"is_infected\":false}]}} (Mock)", error=None)

    global _last_failed_check

    with _offline_lock:
        if time.time() - _last_failed_check < _OFFLINE_CACHE_TTL:
            return ClamAVResult(
                available=False,
                infected=False,
                virus_name=None,
                raw_response="",
                error="ClamAV API offline (cached)",
            )

    url = api_url or _get_api_url()
    
    try:
        with httpx.Client(timeout=60.0) as client:
            with open(path, "rb") as fh:
                files = {"FILES": (path, fh)}
                resp = client.post(f"{url.rstrip('/')}/api/v1/scan", files=files)
            
            resp.raise_for_status()
            data = resp.json()

            if not data.get("success", False):
                _last_failed_check = time.time()
                error_msg = data.get("message", "Unknown upstream error")
                return ClamAVResult(available=False, infected=False, virus_name=None, raw_response=resp.text, error=error_msg)

            results = data.get("data", {}).get("result", [])
            if not results:
                return ClamAVResult(available=True, infected=False, virus_name=None, raw_response=resp.text, error="No result array")

            first_result = results[0]
            is_infected = first_result.get("is_infected", False)
            viruses = first_result.get("viruses", [])

            if is_infected:
                virus_name = viruses[0] if viruses else "Unknown"
                return ClamAVResult(available=True, infected=True, virus_name=virus_name, raw_response=resp.text, error=None)
            
            return ClamAVResult(available=True, infected=False, virus_name=None, raw_response=resp.text, error=None)

    except (httpx.RequestError, httpx.HTTPStatusError, OSError) as exc:
        _last_failed_check = time.time()
        logger.warning("ClamAV REST API unavailable at %s — %s", url, exc)
        return ClamAVResult(
            available=False,
            infected=False,
            virus_name=None,
            raw_response="",
            error=str(exc),
        )
