# Revisor Architecture Analysis & Lessons for Aegis Node

**Target Repository**: `a-sarja/Revisor`  
**License**: MIT  
**Primary Purpose**: Multi-engine malware analysis platform combining ClamAV, YARA, and VirusTotal.  
**Role in Research**: Architecture & Integration Reference  

---

## 1. Architectural Overview of Revisor

Revisor is an open-source multi-engine file analysis system designed to aggregate detection signals from three distinct security engines:

```
                          FILE SUBMISSION
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ Task Dispatch Router  │
                     └───────────┬───────────┘
                                 │
        ┌────────────────────────┼────────────────────────┐
        ▼                        ▼                        ▼
┌───────────────┐        ┌───────────────┐        ┌───────────────┐
│ ClamAV Engine │        │  YARA Engine  │        │  VirusTotal   │
│ (Local Daemon)│        │ (Rule Matcher)│        │ (Cloud API)   │
└───────┬───────┘        └───────┬───────┘        └───────┬───────┘
        │                        │                        │
        └────────────────────────┼────────────────────────┘
                                 │
                                 ▼
                     ┌───────────────────────┐
                     │ Aggregated Assessment │
                     └───────────────────────┘
```

---

## 2. Deep Dive: Engine Interactions

### A. ClamAV Engine Integration
- **Mechanism**: Connects to `clamd` via UNIX socket or TCP port (3310) using the `INSTREAM` or `SCAN` commands.
- **Handling**: Returns signature name (e.g. `Win.Test.EICAR_HDB-1`) if infected, or `OK` if clean.
- **Comparison with Aegis Node**: Aegis Node already implements a custom non-blocking TCP client in [`scanner/clamd_client.py`](file:///c:/Users/sunny/Downloads/AI%20FULL%20STACK%20PROJECT/Aegis-Node/scanner/clamd_client.py) with simulated mock fallback for non-daemon environments.

### B. YARA Rule Engine Integration
- **Mechanism**: Compiles a directory of `.yar` / `.yara` rule files into memory using `yara-python` (`yara.compile(filepaths=...)`).
- **Scanning**: Executes `rules.match(data=...)` on the raw byte stream or file path.
- **Output**: Returns matched rule names, tags, strings, and offsets.
- **Strength**: Extremely fast C-based regex and binary pattern matcher; allows custom community detection signatures.

### C. VirusTotal API Integration
- **Mechanism**: Computes SHA-256 hash and calls VirusTotal REST API v2/v3 endpoint (`GET /api/v3/files/{hash}`).
- **Output**: Returns `positives` / `malicious` engine count (e.g., 14/72 engines flagged as malicious).
- **Limitation in Revisor**: Revisor automatically uploads full files to VirusTotal if the hash is not found in VirusTotal's cache, which presents severe data privacy risks for private/medical/enterprise datasets.

---

## 3. Comparison Matrix: Revisor vs. Aegis Node

| Feature / Dimension | Revisor Implementation | Aegis Node Baseline | Aegis Node Target (Post-Research) |
| :--- | :--- | :--- | :--- |
| **Architecture** | Distributed workers (Celery + Redis) | Monolithic FastAPI + async pipeline | Async in-process multi-engine pipeline (No Redis/Celery) |
| **Antivirus** | ClamAV daemon | ClamAV client + Mock Mode (A-019) | ClamAV client + Mock Mode (Preserved) |
| **Pattern Matching** | YARA rules on raw files | Regex AST/Heuristics on tabular cells | **Curated YARA engine + Tabular Regex Rules** |
| **Threat Intelligence** | Automatic VirusTotal file upload | None (100% offline) | **Privacy-Preserving Hash-First VirusTotal Lookup** |
| **Dataset Sanitization** | None (Analysis & report only) | Deterministic cell-level sanitizer + Re-scan | **Deterministic Sanitizer + Provenance Preservation** |
| **AI/LLM Reasoning** | None | Multi-LLM provider fallback chain | **Multi-LLM Contextual Explanation** |
| **Privacy Model** | Sends full binaries to third parties | Strict zero-external-transmission | **Hash-only external queries with zero dataset leakage** |

---

## 4. Key Lessons & Integration Decisions for Aegis Node

### What to ADOPT / ADAPT from Revisor:
1. **Multi-Engine Evidence Aggregator**:
   - Standardize engine output records into a unified schema:
     ```python
     class EngineDetectionResult(BaseModel):
         engine_name: str          # "clamav", "yara", "heuristics", "virustotal"
         verdict: str              # "CLEAN", "SUSPICIOUS", "MALICIOUS", "UNAVAILABLE"
         severity: str             # "low", "medium", "high", "critical"
         confidence: float         # 0.0 to 1.0
         signatures: list[str]     # ["Eicar-Test-Signature", "PE_Dropper_Pattern"]
         details: dict             # Raw engine metadata
     ```
2. **Curated YARA Pattern Matching**:
   - Add a lightweight YARA scanning stage (`yara-python`) with a tightly curated set of rules targeting embedded PE droppers, shellcode, and obfuscated payloads in datasets.
3. **Hash-First VirusTotal Query**:
   - Implement SHA-256 hash lookup (`/api/v3/files/{hash}`) without uploading dataset bytes.

### What to REJECT from Revisor:
1. **Distributed Queue Overhead**: Reject Celery, Redis, and message brokers. Aegis Node’s async Python execution handles multi-engine scans in < 150 ms without distributed infrastructure.
2. **Automated File Upload to Third Parties**: Reject raw file submission to VirusTotal to protect user dataset privacy and comply with GDPR/HIPAA.
3. **Blind Severity Scoring**: In Revisor, any engine detection marks the file malicious. In Aegis Node, research metadata (e.g. `MAL-009` WannaCry research reference) is contextually disambiguated from active malware artifacts.
