import logging
import os
import threading
import time
from typing import Any

import httpx

from .base import AntivirusProvider, AVScanResult

logger = logging.getLogger(__name__)

# Cache offline status for 5 seconds to avoid repeated socket timeouts when daemon is down
_OFFLINE_CACHE_TTL = 5.0
_last_failed_check: float = 0.0
_offline_lock = threading.Lock()


def _extract_version(payload: Any) -> str | None:
    if not isinstance(payload, dict) or payload.get("success") is not True:
        return None

    version_data = payload.get("data")
    if isinstance(version_data, str):
        version = version_data
    elif isinstance(version_data, dict):
        version = version_data.get("version") or version_data.get("clamav_version")
    else:
        return None

    if not isinstance(version, str):
        return None
    version = version.strip()
    return version or None


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
                resp.raise_for_status()
                return _extract_version(resp.json()) is not None
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("ClamAV REST API health check failed at %s: %s", self.api_url, exc)
        return False

    def get_version(self) -> str:
        if self.mock_mode:
            return "ClamAV (Mock)"
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"{self.api_url}/api/v1/version")
                resp.raise_for_status()
                version = _extract_version(resp.json())
                if version is not None:
                    return version
                logger.warning("ClamAV REST API returned an invalid version response at %s", self.api_url)
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            logger.warning("Unable to retrieve ClamAV version from %s: %s", self.api_url, exc)
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

                if not isinstance(data, dict):
                    raise ValueError("Invalid ClamAV response: expected a JSON object")
                if data.get("success") is not True:
                    _last_failed_check = time.time()
                    error_msg = data.get("message")
                    if not isinstance(error_msg, str) or not error_msg.strip():
                        error_msg = "ClamAV scan request was not successful"
                    return AVScanResult(available=False, infected=False, virus_name=None, raw_response=resp.text, error=error_msg)

                result_data = data.get("data")
                if not isinstance(result_data, dict):
                    raise ValueError("Invalid ClamAV response: missing data object")
                results = result_data.get("result")
                if not isinstance(results, list) or not results:
                    raise ValueError("Invalid ClamAV response: missing scan result")

                first_result = results[0]
                if not isinstance(first_result, dict):
                    raise ValueError("Invalid ClamAV response: scan result must be an object")
                is_infected = first_result.get("is_infected")
                if not isinstance(is_infected, bool):
                    raise ValueError("Invalid ClamAV response: is_infected must be a boolean")
                viruses = first_result.get("viruses", [])
                if not isinstance(viruses, list) or any(not isinstance(virus, str) for virus in viruses):
                    raise ValueError("Invalid ClamAV response: viruses must be a list of strings")

                _last_failed_check = 0.0
                if is_infected:
                    virus_name = next((virus.strip() for virus in viruses if virus.strip()), None)
                    return AVScanResult(available=True, infected=True, virus_name=virus_name, raw_response=resp.text, error=None)

                return AVScanResult(available=True, infected=False, virus_name=None, raw_response=resp.text, error=None)

        except (httpx.HTTPError, OSError, ValueError, TypeError) as exc:
            _last_failed_check = time.time()
            if isinstance(exc, httpx.HTTPStatusError):
                logger.warning(f"ClamAV REST API unavailable at {self.api_url} - {exc}. Response: {exc.response.text}")
            else:
                logger.warning("ClamAV scan failed at %s: %s", self.api_url, exc)
            return AVScanResult(
                available=False,
                infected=False,
                virus_name=None,
                raw_response=resp.text if "resp" in locals() else "",
                error=str(exc),
            )
