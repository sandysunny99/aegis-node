# VirusTotal API v3 Integration Specification

**Component**: `backend/services/integrations/virustotal_client.py`  
**Protocol**: REST HTTPS (API v3)  
**Authentication**: Header `x-apikey: {VIRUSTOTAL_API_KEY}`  
**Integration Status**: Specification & Prototype Design  

---

## 1. API Contract & Data Model

### A. Endpoint Target
`GET https://www.virustotal.com/api/v3/files/{sha256}`

### B. Normalized Response Model
```python
from pydantic import BaseModel, Field


class VirusTotalReputationResult(BaseModel):
    provider: str = "virustotal"
    status: str  # "COMPLETED", "NOT_FOUND", "RATE_LIMITED", "UNCONFIGURED", "ERROR"
    sha256: str
    positives: int = 0
    total_engines: int = 0
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    popular_threat_name: str | None = None
    reputation_score: int = 0
    permalink: str | None = None
    error_message: str | None = None
```

---

## 2. Asynchronous Client Implementation Logic

```python
import logging
import httpx
from config import settings

logger = logging.getLogger(__name__)

_VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
_TIMEOUT_SECONDS = 8.0


async def lookup_file_hash(sha256: str) -> VirusTotalReputationResult:
    """
    Query VirusTotal API v3 by SHA-256 checksum.
    Never uploads dataset files — operates strictly on the cryptographic hash.
    """
    api_key = (settings.virustotal_api_key or "").strip()
    if not api_key:
        return VirusTotalReputationResult(
            status="UNCONFIGURED",
            sha256=sha256,
            error_message="VIRUSTOTAL_API_KEY not configured",
        )

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.get(f"{_VT_BASE_URL}/{sha256}", headers=headers)

            if resp.status_code == 404:
                return VirusTotalReputationResult(
                    status="NOT_FOUND",
                    sha256=sha256,
                    error_message="Hash not present in VirusTotal global database",
                )
            if resp.status_code == 429:
                return VirusTotalReputationResult(
                    status="RATE_LIMITED",
                    sha256=sha256,
                    error_message="VirusTotal rate limit exceeded (4 req/min free tier)",
                )

            resp.raise_for_status()
            data = resp.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            threat_class = attributes.get("popular_threat_classification", {})
            suggested_name = threat_class.get("suggested_threat_label")

            return VirusTotalReputationResult(
                status="COMPLETED",
                sha256=sha256,
                positives=malicious + suspicious,
                total_engines=total,
                malicious=malicious,
                suspicious=suspicious,
                harmless=harmless,
                undetected=undetected,
                popular_threat_name=suggested_name,
                reputation_score=attributes.get("reputation", 0),
                permalink=f"https://www.virustotal.com/gui/file/{sha256}",
            )

    except Exception as exc:  # noqa: BLE001
        logger.warning("VirusTotal lookup failed for hash %s: %s", sha256[:12], exc)
        return VirusTotalReputationResult(
            status="ERROR",
            sha256=sha256,
            error_message=f"VirusTotal connection error: {exc}",
        )
```

---

## 3. Threat Scoring & Policy Fusion

The VirusTotal result is integrated into Aegis Node's Multi-Engine Risk Score:

$$\text{External Risk} = \begin{cases} 
1.0 & \text{if } \text{malicious} \ge 5 \\
0.6 & \text{if } 1 \le \text{malicious} < 5 \text{ or } \text{suspicious} \ge 3 \\
0.0 & \text{otherwise (clean or unconfigured)}
\end{cases}$$

This external signal is fused with local ClamAV, YARA, and heuristic evidence, ensuring that external API unavailability never degrades local detection capability.
