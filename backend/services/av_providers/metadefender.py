import logging
import time
import os
import httpx

from .base import AntivirusProvider, AVScanResult

logger = logging.getLogger(__name__)

class MetaDefenderProvider(AntivirusProvider):
    def __init__(self, api_key: str, base_url: str = "https://api.metadefender.com/v4"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "apikey": self.api_key
        }

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
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self.base_url}/apikey/", headers=self.headers)
                return resp.status_code == 200
        except Exception:
            pass
        return False

    def get_version(self) -> str:
        return "MetaDefender Cloud"

    def scan_file(self, path: str) -> AVScanResult:
        if not self.api_key:
            return AVScanResult(available=False, infected=False, virus_name=None, raw_response="", error="Missing MetaDefender API key")

        try:
            file_size = os.path.getsize(path)
            with httpx.Client(timeout=60.0) as client:
                # 1. Upload file
                with open(path, "rb") as fh:
                    upload_headers = self.headers.copy()
                    upload_headers["Content-Type"] = "application/octet-stream"
                    upload_headers["Content-Length"] = str(file_size)
                    upload_headers["filename"] = os.path.basename(path)
                    
                    resp = client.post(f"{self.base_url}/file", headers=upload_headers, content=fh)
                
                if resp.status_code == 429:
                    return AVScanResult(available=False, infected=False, virus_name=None, raw_response=resp.text, error="MetaDefender API rate limit exceeded (429)")

                resp.raise_for_status()
                data = resp.json()
                
                data_id = data.get("data_id")
                if not data_id:
                    return AVScanResult(available=False, infected=False, virus_name=None, raw_response=resp.text, error="No data_id returned from upload")

                # 2. Poll for report
                max_retries = 30
                retry_delay = 2.0
                
                for attempt in range(max_retries):
                    time.sleep(retry_delay)
                    poll_resp = client.get(f"{self.base_url}/file/{data_id}", headers=self.headers)
                    
                    if poll_resp.status_code == 429:
                        retry_after = int(poll_resp.headers.get("Retry-After", 5))
                        # Cap retry after
                        retry_after = min(retry_after, 30)
                        time.sleep(retry_after)
                        continue
                        
                    poll_resp.raise_for_status()
                    report_data = poll_resp.json()
                    
                    progress_pct = report_data.get("scan_results", {}).get("progress_percentage", 0)
                    
                    if progress_pct == 100:
                        scan_results = report_data.get("scan_results", {})
                        scan_all_result_i = scan_results.get("scan_all_result_i", 0)
                        
                        if scan_all_result_i == 0:
                            return AVScanResult(available=True, infected=False, virus_name=None, raw_response=poll_resp.text, error=None)
                        elif scan_all_result_i in [1, 2]:
                            virus_name = "Unknown Threat"
                            details = scan_results.get("scan_details", {})
                            for engine, result in details.items():
                                if result.get("threat_found"):
                                    virus_name = result.get("threat_found")
                                    break
                            return AVScanResult(available=True, infected=True, virus_name=virus_name, raw_response=poll_resp.text, error=None)
                        elif scan_all_result_i == 3:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_SCAN_FAILED")
                        elif scan_all_result_i == 7:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_SKIPPED_CLEAN")
                        elif scan_all_result_i == 8:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_SKIPPED_INFECTED")
                        elif scan_all_result_i == 9:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_EXCEEDED_ARCHIVE_DEPTH")
                        elif scan_all_result_i == 10:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_NOT_SCANNED")
                        elif scan_all_result_i == 11:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_ABORTED")
                        elif scan_all_result_i == 12:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_ENCRYPTED")
                        elif scan_all_result_i == 13:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error="METADEFENDER_EXCEEDED_ARCHIVE_SIZE")
                        else:
                            return AVScanResult(available=False, infected=False, virus_name=None, raw_response=poll_resp.text, error=f"METADEFENDER_UNKNOWN_RESULT_{scan_all_result_i}")

                return AVScanResult(available=False, infected=False, virus_name=None, raw_response="", error="MetaDefender scan timeout (polling limit exceeded)")

        except (httpx.RequestError, httpx.HTTPStatusError, OSError) as exc:
            logger.warning(f"MetaDefender API unavailable - {exc}")
            return AVScanResult(
                available=False,
                infected=False,
                virus_name=None,
                raw_response="",
                error=str(exc),
            )
