# Aegis Node — GitHub Research Baseline

**Document Type**: Codebase & Architecture Baseline Audit  
**Version**: 1.0.0  
**Status**: Completed & Verified (243/243 Tests Passing)  
**Target Repository**: [https://github.com/sandysunny99/aegis-node](https://github.com/sandysunny99/aegis-node)  

---

## 1. Current Architectural Baseline

Aegis Node is an AI-assisted framework designed for secure tabular/structured dataset ingestion, multi-stage threat detection, evidence-grounded AI explanation, deterministic cell-level remediation, and mandatory re-scan verification.

```
                      UPLOAD (CSV, JSON, JSONL, Parquet, XLSX, TXT)
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │ 1. INGESTION & BOUNDARY DEFENSE           │
                  │  • Direct-to-Disk Streaming (0.14 MB RAM) │
                  │  • Incremental SHA-256 Checksumming       │
                  │  • Magic-Byte File Type Verification      │
                  │  • Cloudflare Turnstile Anti-Bot Shield   │
                  │  • 60 req/min Rate Limiting (SlowAPI)     │
                  └─────────────────────┬─────────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │ 2. DETERMINISTIC DETECTION ENGINE         │
                  │  • Stage 0: Raw Binary Inspection         │
                  │  • Stage 0.5: Heuristic Risk Scorer       │
                  │  • Stage 1: ClamAV Antivirus Daemon Ping  │
                  │  • Stage 2: Context-Aware Regex Rules:    │
                  │     - CSV / Excel Formula Injection (DDE) │
                  │     - Script / XSS Payloads (<script>)    │
                  │     - SQL Injection (UNION, OR 1=1)       │
                  │     - Null Bytes & Path Traversal         │
                  │     - Research vs Artifact Disambiguation │
                  └─────────────────────┬─────────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │ 3. MULTI-AI EXPLANATION LAYER             │
                  │  • Isolated Prompt Framing (<UNTRUSTED>)  │
                  │  • Fallback Chain: Gemini ➔ Cloudflare    │
                  │    Workers AI ➔ xAI Grok ➔ Groq Llama 3   │
                  │  • Structured JSON Validation & Filtering │
                  └─────────────────────┬─────────────────────┘
                                        │
                                        ▼
                  ┌───────────────────────────────────────────┐
                  │ 4. DETERMINISTIC REMEDIATION & VERIFICATION│
                  │  • Cell-Level Prefix Neutralization       │
                  │  • Provenance Preservation (Original R/O) │
                  │  • Mandatory Post-Remediation Re-Scan     │
                  │  • Single-Use 60-min Download Token       │
                  └───────────────────────────────────────────┘
```

---

## 2. Component-by-Component Baseline Audit

| Component | File / Location | Current Implementation | Strengths | Weaknesses / Limitations | Candidate OSS Replacement / Enhancement |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **File Validation & Magic Bytes** | `backend/services/file_service.py` | Custom byte header inspection (`PK\x03\x04`, `PAR1`, `\xef\xbb\xbf`) | Zero-dependency, memory-safe, fast (< 1 ms) | Limited to 6 supported extensions; lacks deep container unpacking | Python `filetype` or `python-magic` (libmagic) |
| **Streaming Upload & Checksum** | `backend/services/file_service.py` | 1 MB chunk streaming with `hashlib.sha256()` | RAM consumption strictly bounded at 0.14 MB regardless of file size (up to 500 MB) | Single-threaded hashing per request | Maintain existing custom implementation (Optimal) |
| **Raw Binary & Header Scanner** | `scanner/engine.py` (Stage 0) | Checks for embedded MZ/PE, ELF, Mach-O, shellcode prefixes | Catches embedded executables inside CSV/JSON | Naive binary pattern matching; lacks disassembly/PE header parsing | YARA pattern matching engine (`yara-python`) |
| **Heuristic Anomaly Detection** | `scanner/heuristics.py` (Stage 0.5) | Shannon entropy calculation, character frequency distribution, high-entropy token density | Very fast, detects obfuscated/base64 blobs without ML overhead | Cannot distinguish benign compressed data from encrypted shellcode | Normalization & multi-encoding decoders (Prompt Shield technique) |
| **Antivirus Scanner** | `scanner/clamd_client.py` (Stage 1) | Custom TCP socket client communicating with `clamd` (INSTREAM command) | Zero-dependency, non-blocking, handles mock mode gracefully | Limited to ClamAV signature database; high RAM if daemon runs locally (1.2 GB) | ClamAV + YARA rule engine + VirusTotal hash lookup (Revisor pattern) |
| **Rule-Based Context Checker** | `scanner/content_checker.py` (Stage 2) | Compiled regular expressions for Formula, Script, SQLi, Null Bytes, Malware References | Context-aware (`MAL-009` research vs active artifact); 0.0% FP on clean data | Regex rules can be bypassed by multi-stage obfuscation, token splitting, or homoglyphs | Vigil / Prompt Armor multi-layer normalization & token boundary analysis |
| **Prompt Injection Detection** | `scanner/content_checker.py` & `llm_service.py` | Regex patterns (`IGNORE PREVIOUS`, `SYSTEM PROMPT`) + XML tag isolation (`<UNTRUSTED_DATA>`) | Isolates LLM prompt from user input; rejects instructions embedded in data | Keyword-heavy; vulnerable to semantic reframing, base64 payload splitting, foreign languages | Semantic embedding similarity (Vigil / Prompt Armor / Rebuff) + Held-out benchmark evaluation |
| **External Threat Intelligence** | *None* (Currently purely local) | No external CTI lookups | 100% offline capability, zero API latency, zero external data leakage | Cannot verify whether a SHA-256 hash or C2 IP is known across global threat networks | VirusTotal API v3 hash-first lookup + AbuseIPDB for IP reputation |
| **AI Explanation & Fallback** | `backend/services/llm_service.py` | Multi-provider fallback (`gemini`, `cloudflare`, `xai`, `groq`, `ollama`) | High resilience; zero downtime when single provider runs out of credits | Output schema relies on post-parsing validation rather than constrained grammar decoding | Outlines / instructor schema enforcement (Reference only) |
| **Remediation & Sanitization** | `scanner/sanitizer.py` & `backend/routers/remediation.py` | Non-destructive cell-level formula quote-prefixing, script tag escaping, null byte stripping | Preserves tabular structure, preserves research metadata, produces diff records | Operates row-by-row; lacks schema-aware column data typing | Maintain custom sanitizer + add encoding normalization |
| **Post-Remediation Re-Scan** | `backend/routers/remediation.py` | Mandatory re-scan of sanitized file before issuing download token | Guarantees threat neutralization, verifies SHA-256 divergence | Re-scans entire file synchronously | Maintain existing custom implementation (Authoritative invariant) |

---

## 3. Existing Dependencies & Footprint

- **Backend (Python 3.12)**:
  - `fastapi`, `uvicorn`, `pydantic`, `pydantic-settings`
  - `sqlalchemy` (SQLite local database)
  - `slowapi` (In-memory rate limiting)
  - `httpx` (Asynchronous HTTP client for AI providers and Cloudflare Turnstile)
  - `pandas`, `openpyxl`, `pyarrow` (Tabular format parsing)
  - `pytest`, `pytest-asyncio` (Test framework - 243 passing tests)
- **Frontend (React 18 + Vite)**:
  - Zero heavy component libraries (pure CSS design system)
  - Built size: 188 KB JS, 8.4 KB CSS (loads in < 150 ms)
- **Deployment**:
  - Docker container on Render / local Docker Compose with optional ClamAV daemon.

---

## 4. Key Takeaways for Open-Source Research

1. **Aegis Node's Ingestion & Remediation are Strong**: Direct-to-disk streaming, RAM boundness (0.14 MB), cell-level quote prefixing, and mandatory post-remediation re-scan are already mature and must remain custom.
2. **Key Weaknesses to Improve via Open-Source Research**:
   - Lack of standard **YARA rule support** for deep pattern matching.
   - Lack of **VirusTotal / CTI reputation enrichment** by SHA-256 hash.
   - Prompt-injection scanner relies heavily on keyword matching and can be enhanced with **normalization and multi-encoding decoders**.
3. **Guardrails**:
   - Must NOT adopt heavy ML frameworks (e.g. PyTorch, TensorFlow, large transformers) that exceed Render's 512 MB free RAM tier.
   - Must maintain 100% offline functionality if external APIs are unreachable.
