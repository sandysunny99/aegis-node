import logging
import os
import threading
import time
import httpx

from .base import AntivirusProvider, AVScanResult

logger = logging.getLogger(__name__)

# Cache offline status for 5 seconds to avoid repeated socket timeouts when daemon is down
_OFFLINE_CACHE_TTL = 5.0
_last_failed_check: float = 0.0
_offline_lock = threading.Lock()

class ClamAVRestProvider(AntivirusProvider):
    def __init__(self, api_url: str, mock_mode: bool = False):
        self.api_url = api_url.rstrip("/")
        if not self.api_url.startswith("http"):
            self.api_url = f"http://{self.api_url}"
        self.mock_mode = mock_mode

    @property
    def provider_name(self) -> str:
        return "clamav_rest"

    @property
    def provider_authority(self) -> str:
        return "local_deterministic"

    def ping(self) -> bool:
        if self.mock_mode:
            return True
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self.api_url}/api/v1/version")
                if resp.status_code == 200:
                    data = resp.json()
                    return data.get("success", False)
        except Exception:
            pass
        return False

    def get_version(self) -> str:
        if self.mock_mode:
            return "ClamAV (Mock)"
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self.api_url}/api/v1/version")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("success"):
                        version_data = data.get("data")
                        if isinstance(version_data, str):
                            return version_data
                        elif isinstance(version_data, dict):
                            ver = version_data.get("version") or version_data.get("clamav_version", "Unknown")
                            return ver.strip()
                        return "Unknown"
        except Exception:
            pass
        return "Unavailable"

    def scan_file(self, path: str) -> AVScanResult:
        if self.mock_mode:
            return AVScanResult(available=True, infected=False, virus_name=None, raw_response='{"success":true,"data":{"result":[{"is_infected":false}]}} (Mock)', error=None)

        global _last_failed_check

        with _offline_lock:
            if time.time() - _last_failed_check < _OFFLINE_CACHE_TTL:
                return AVScanResult(
                    available=False,
                    infected=False,
                    virus_name=None,
                    raw_response="",
                    error="ClamAV API offline (cached)",
                )

        try:
            with httpx.Client(timeout=60.0) as client:
                with open(path, "rb") as fh:
                    filename = os.path.basename(path)
                    files = {"FILES": (filename, fh, "application/octet-stream")}
                    resp = client.post(f"{self.api_url}/api/v1/scan", files=files)
                
                resp.raise_for_status()
                data = resp.json()

                if not data.get("success", False):
                    _last_failed_check = time.time()
                    error_msg = data.get("message", "Unknown upstream error")
                    return AVScanResult(available=False, infected=False, virus_name=None, raw_response=resp.text, error=error_msg)

                results = data.get("data", {}).get("result", [])
                if not results:
                    return AVScanResult(available=True, infected=False, virus_name=None, raw_response=resp.text, error="No result array")

                first_result = results[0]
                is_infected = first_result.get("is_infected", False)
                viruses = first_result.get("viruses", [])

                if is_infected:
                    virus_name = viruses[0] if viruses else "Unknown"
                    return AVScanResult(available=True, infected=True, virus_name=virus_name, raw_response=resp.text, error=None)
                
                return AVScanResult(available=True, infected=False, virus_name=None, raw_response=resp.text, error=None)

        except (httpx.RequestError, httpx.HTTPStatusError, OSError) as exc:
            _last_failed_check = time.time()
            if isinstance(exc, httpx.HTTPStatusError):
                logger.warning(f"ClamAV REST API unavailable at {self.api_url} - {exc}. Response: {exc.response.text}")
            else:
                logger.warning(f"ClamAV REST API unavailable at {self.api_url} - {exc}")
            return AVScanResult(
                available=False,
                infected=False,
                virus_name=None,
                raw_response="",
                error=str(exc),
            )

