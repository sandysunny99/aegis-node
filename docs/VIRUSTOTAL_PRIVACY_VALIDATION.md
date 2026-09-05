# VirusTotal Integration — Privacy Validation & Threat Model

**Component**: `backend/services/integrations/virustotal.py`  
**Security Standard**: Privacy-First Zero Dataset Content Transmission  

---

## 1. Threat Model & Privacy Guarantee

When handling proprietary, academic, medical, or security research datasets, transmitting raw file content to external multi-engine antivirus services introduces severe confidentiality and compliance risks (GDPR, HIPAA, IP leakage).

### Aegis Node Privacy Guarantees:
1. **Zero Content Transmission**: Aegis Node calculates the SHA-256 hash locally during direct-to-disk streaming ingestion. Only the 64-character hexadecimal SHA-256 string is transmitted in the URL path (`GET /api/v3/files/{sha256}`).
2. **Zero Body Upload**: The HTTP request contains no request payload body, no CSV rows, no JSON properties, and no cell values.
3. **Opt-In Architecture**: VirusTotal integration is **DISABLED by default** (`ENABLE_VIRUSTOTAL=false`). The local multi-stage scanner functions 100% offline without requiring any external keys or network calls.

---

## 2. Experimental Verification of Hash-First Transmission

In `tests/test_virustotal_adapter.py`, the network inspection fixture validates that:
1. The outgoing request method is strictly `GET`.
2. The URL matches `https://www.virustotal.com/api/v3/files/[a-f0-9]{64}`.
3. The request body (`data` or `json`) is empty / `None`.
4. When `ENABLE_VIRUSTOTAL=false`, zero outgoing HTTP network requests are initiated.
