import logging
import time
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
                # MetaDefender API check using hash lookup of a known clean file or stat endpoint
                # Since ping is just a readiness check, we can check the stat/appinfo endpoint
                resp = client.get(f"{self.base_url}/stat/node", headers=self.headers)
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
            with httpx.Client(timeout=30.0) as client:
                # 1. Upload file
                with open(path, "rb") as fh:
                    # MetaDefender v4 expects binary data in body or multipart. Binary body is standard.
                    # We will use headers {"filename": ...} if needed, but binary upload to /file is standard.
                    upload_headers = self.headers.copy()
                    upload_headers["Content-Type"] = "application/octet-stream"
                    resp = client.post(f"{self.base_url}/file", headers=upload_headers, content=fh.read())
                
                if resp.status_code == 429:
                    return AVScanResult(available=False, infected=False, virus_name=None, raw_response=resp.text, error="MetaDefender API rate limit exceeded (429)")

                resp.raise_for_status()
                data = resp.json()
                
                data_id = data.get("data_id")
                if not data_id:
                    return AVScanResult(available=False, infected=False, virus_name=None, raw_response=resp.text, error="No data_id returned from upload")

                # 2. Poll for report
                max_retries = 15
                retry_delay = 2.0
                
                for attempt in range(max_retries):
                    time.sleep(retry_delay)
                    poll_resp = client.get(f"{self.base_url}/file/{data_id}", headers=self.headers)
                    
                    if poll_resp.status_code == 429:
                        # Throttle limit hit during polling
                        retry_after = int(poll_resp.headers.get("Retry-After", 5))
                        time.sleep(retry_after)
                        continue
                        
                    poll_resp.raise_for_status()
                    report_data = poll_resp.json()
                    
                    # 100 means completed, numbers below 100 mean in progress
                    progress_pct = report_data.get("scan_results", {}).get("progress_percentage", 0)
                    
                    if progress_pct == 100:
                        scan_results = report_data.get("scan_results", {})
                        scan_all_result_i = scan_results.get("scan_all_result_i", 0)
                        
                        # 0 = clean, 1 = infected, 2 = suspicious, etc.
                        is_infected = scan_all_result_i in [1, 2]
                        
                        if is_infected:
                            # Try to extract a virus name from the engines
                            virus_name = "Unknown Threat"
                            details = scan_results.get("scan_details", {})
                            for engine, result in details.items():
                                if result.get("threat_found"):
                                    virus_name = result.get("threat_found")
                                    break
                            
                            return AVScanResult(available=True, infected=True, virus_name=virus_name, raw_response=poll_resp.text, error=None)
                        else:
                            return AVScanResult(available=True, infected=False, virus_name=None, raw_response=poll_resp.text, error=None)

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
