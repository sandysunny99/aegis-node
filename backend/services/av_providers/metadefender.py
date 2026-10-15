"""
MetaDefender Cloud as a hash-only antivirus provider.

Only the file's SHA-256 leaves the server (GET /v4/hash/{sha256}); the file is never
uploaded (Phase A gap #17, AGENTS.md). A hash MetaDefender has never seen returns
available=False with METADEFENDER_HASH_NOT_FOUND, so a scan can never pass as
verified because of it. Most user datasets are unique files, so "not found" is the
expected answer for them.
"""

import hashlib
import logging

import httpx

from .base import AntivirusProvider, AVScanResult

logger = logging.getLogger(__name__)

# scan_all_result_i codes that mean MetaDefender has no usable verdict for the file
_NO_VERDICT_CODES = {
    3: "METADEFENDER_SCAN_FAILED",
    7: "METADEFENDER_SKIPPED_CLEAN",
    8: "METADEFENDER_SKIPPED_INFECTED",
    9: "METADEFENDER_EXCEEDED_ARCHIVE_DEPTH",
    10: "METADEFENDER_NOT_SCANNED",
    11: "METADEFENDER_ABORTED",
    12: "METADEFENDER_ENCRYPTED",
    13: "METADEFENDER_EXCEEDED_ARCHIVE_SIZE",
}


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _unavailable(error: str, raw: str = "") -> AVScanResult:
    return AVScanResult(available=False, infected=False, virus_name=None, raw_response=raw, error=error)


class MetaDefenderProvider(AntivirusProvider):
    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.metadefender.com/v4",
        timeout_seconds: float = 15.0,
        transport: httpx.BaseTransport | None = None,
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.headers = {"apikey": self.api_key}
        self._transport = transport  # tests inject httpx.MockTransport

    def _client(self) -> httpx.Client:
        return httpx.Client(timeout=self.timeout_seconds, transport=self._transport)

    @property
    def provider_name(self) -> str:
        return "metadefender"

    @property
    def provider_authority(self) -> str:
        return "external_evidence"

    def ping(self) -> bool:
        if not self.api_key:
            return False
        try:
            with self._client() as client:
                resp = client.get(f"{self.base_url}/apikey/", headers=self.headers)
                return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def get_version(self) -> str:
        return "MetaDefender Cloud (hash lookup only)"

    def scan_file(self, path: str) -> AVScanResult:
        if not self.api_key:
            return _unavailable("Missing MetaDefender API key")

        try:
            sha256 = _sha256(path)
            with self._client() as client:
                resp = client.get(f"{self.base_url}/hash/{sha256}", headers=self.headers)
        except (httpx.HTTPError, OSError) as exc:
            logger.warning("MetaDefender hash lookup unavailable: %s", exc)
            return _unavailable(str(exc))

        if resp.status_code == 404:
            return _unavailable("METADEFENDER_HASH_NOT_FOUND", resp.text)
        if resp.status_code == 429:
            return _unavailable("MetaDefender API rate limit exceeded (429)", resp.text)
        if resp.status_code in (401, 403):
            return _unavailable(f"MetaDefender auth error ({resp.status_code})", resp.text)
        if resp.status_code != 200:
            return _unavailable(f"MetaDefender HTTP {resp.status_code}", resp.text)

        try:
            scan_results = resp.json().get("scan_results", {})
            code = scan_results.get("scan_all_result_i")
        except (ValueError, AttributeError):
            return _unavailable("Invalid MetaDefender response", resp.text)

        if code == 0:
            return AVScanResult(available=True, infected=False, virus_name=None, raw_response=resp.text, error=None)
        if code in (1, 2):
            virus_name = next(
                (r.get("threat_found") for r in scan_results.get("scan_details", {}).values()
                 if isinstance(r, dict) and r.get("threat_found")),
                "Unknown Threat",
            )
            return AVScanResult(available=True, infected=True, virus_name=virus_name, raw_response=resp.text, error=None)
        return _unavailable(_NO_VERDICT_CODES.get(code, f"METADEFENDER_UNKNOWN_RESULT_{code}"), resp.text)
