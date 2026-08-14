# 🛡️ Aegis Node — Dataset Threat Detection & Remediation Platform

An enterprise-grade, security-hardened dataset threat detection and automated remediation platform. Aegis Node scans datasets (CSV, JSON, JSONL, Parquet, XLSX, TXT) for malware, formula injections, script injections, and SQL anomalies, explains findings using AI, and neutralizes threats in-place while maintaining schema integrity.

[![Build Status](https://img.shields.io/badge/tests-184%20passed-success)](https://github.com/sandysunny99/aegis-node)
[![Python](https://img.shields.io/badge/python-3.12-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-009688)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18-61dafb)](https://react.dev/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ed)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-green)](#license)

---

## 📌 Key Capabilities & Security Hardening

| Category | Features & Technical Highlights |
|----------|---------------------------------|
| 🔍 **Multi-Stage Detection Engine** | **Stage 0** raw byte scan (EICAR/PE/ELF) → **Stage 0.5** heuristics (entropy, packers, injection APIs) → ClamAV INSTREAM → **27-rule** Regex Engine. |
| ⚡ **Threat Neutralization** | Neutralizes Formula Injections (`=`, `@`, `+`, `-`, `DDE`, `HYPERLINK`), Script/XSS Tags, SQL Injection patterns, and Null bytes. |
| 🧹 **Deobfuscation Pipeline** | Recursive URL decoding, HTML entity unescaping, SQL comment stripping, and whitespace normalization prior to pattern matching. |
| 🤖 **Multi-Provider AI Analysis** | Real-time threat explanation via Google Gemini, xAI Grok (auto-failover), Groq Cloud (Llama 3.1), or offline Ollama with fallback chains. |
| 🛡️ **Hardened Security Architecture** | Evaluated against 38 security & architectural audit findings. Includes magic-byte header validation, chunked upload streaming, single-use download tokens, and strict `Cache-Control` response guards. |
| ⚡ **Database & Performance** | SQLite WAL mode (`PRAGMA journal_mode=WAL`) for high-concurrency connection handling without database lock failures. |
| 📊 **Format Support** | Full native support for `.csv`, `.json`, `.jsonl`, `.parquet`, `.xlsx`, and `.txt` format datasets. |
| 📋 **Audit & Scan History** | Persistent SQLite-backed history tracking all scans, risk scores, threat breakdowns, and single-use download tokens. |
| 🚀 **Cloud & Docker Ready** | Blueprint configured for 1-click [Render.com](https://render.com) deployment or multi-container `docker compose` orchestration. |

---

## 🏗️ System Architecture

```text
               ┌──────────────────────────────────────────────┐
               │    React 18 + Vite Frontend (UI Dashboard)   │
               └──────────────────────┬───────────────────────┘
                                      │ REST API (XHR + Progress)
                                      ▼
               ┌──────────────────────────────────────────────┐
               │         FastAPI Backend (Python 3.12)        │
               │   • SlowAPI IP Rate Limiter                  │
               │   • Magic-Byte File Type Validator           │
               │   • Single-Use Token Remediation Controller  │
               └──────┬───────────────────────┬───────────────┘
                      │                       │
         ┌────────────┴──────────┐   ┌────────┴─────────────────────┐
         ▼                       ▼   ▼                             ▼
 ┌───────────────┐       ┌───────────────┐                 ┌───────────────┐
 │ ClamAV Daemon │       │ Scanner Engine│                 │ AI Provider   │
 │ (INSTREAM /   │       │ • Deobfuscator│                 │ Router        │
 │  Mock Mode)   │       │ • 9 Rules     │                 │ • Gemini      │
 └───────────────┘       └───────┬───────┘                 │ • Groq        │
                                 │                         │ • Ollama      │
                                 ▼                         └───────────────┘
                         ┌───────────────┐
                         │   Sanitizer   │
                         │ neutralizes   │
                         │ cell payload  │
                         └───────────────┘
```

---

## 🧪 Test Results

```
pytest tests/ -v
184 passed in 13.21s
```

| Test Module | Tests | Coverage |
|---|---|---|
| `test_heuristics.py` | **33** (NEW) | Entropy math, HEUR-001…HEUR-008, engine integration, disable flag |
| `test_real_samples.py` | 18 | Raw bytes scan, EICAR, PE/ELF, real samples, full pipeline |
| `test_scanner_rules.py` | 26 | All 27 detection rules, deobfuscation |
| `test_scanner.py` | 12 | Engine verdicts, format support, SHA-256 |
| `test_sanitizer.py` | 13 | Formula/script/SQL/null-byte neutralization |
| `test_security.py` | 11 | AI output validation, prompt injection defence |
| `test_upload.py` | 7 | Upload, magic-byte validation, SHA-256 |
| `test_remediation.py` | 5 | Remediation, download token, path traversal |
| `test_llm.py` | 6 | AI provider chain, fallback, mocked calls |
| `test_api.py` + `test_smoke.py` | 53 | API endpoints, auth, rate limiting, health |

---

## 🛡️ Detection Rules Reference

### Stage 0 — Raw Bytes Scan (Before Parsing)
| Rule | Category | Severity | What it Detects |
|---|---|---|---|
| MAL-001 | `malware_signature` | **Critical** | EICAR antivirus test string (exact bytes) |
| MAL-002 | `malware_signature` | **Critical** | Windows PE/MZ executable header |
| MAL-003 | `malware_signature` | **Critical** | ELF Linux/Unix binary header |
| MAL-011 | `shellcode` | High | NOP sled (`\x90 * 12+`) shellcode pattern |

### Stage 2 — Content Inspection Rules
| Rule | Category | Severity | What it Detects |
|---|---|---|---|
| FORM-001 | `formula_injection` | High | CSV formula triggers (`=`,`+`,`-`,`@`,`\|`) |
| FORM-002 | `formula_injection` | **Critical** | DDE/cmd/PowerShell formula payload |
| FORM-003 | `formula_injection` | High | HYPERLINK external URL formula |
| SCRP-001 | `script_injection` | **Critical** | `<script>` HTML/JS tag |
| SCRP-002 | `script_injection` | High | `javascript:` protocol handler |
| SCRP-003 | `script_injection` | High | `eval()` / `exec()` call |
| SQLI-001 | `sql_injection` | High | Classic SQL injection (`OR 1=1`, `DROP TABLE`) |
| SQLI-002 | `sql_injection` | High | `UNION SELECT` injection |
| BIN-001 | `binary_anomaly` | Medium | Null byte `\x00` in text field |
| MAL-001 | `malware_signature` | **Critical** | EICAR string in cell value |
| MAL-002 | `malware_signature` | **Critical** | MZ/PE header string in cell |
| MAL-003 | `malware_signature` | **Critical** | ELF header string in cell |
| MAL-004 | `malware_signature` | **Critical** | Base64-encoded PE (TVoA/TVJQ prefix) |
| MAL-005 | `shellcode` | **Critical** | PowerShell `-EncodedCommand` |
| MAL-006 | `shellcode` | **Critical** | IEX / DownloadString / WebClient cradle |
| MAL-007 | `shellcode` | High | Reverse shell (`/dev/tcp`, `nc -e /bin/sh`) |
| MAL-008 | `macro_threat` | High | Auto-execute macros (AutoOpen, WScript.Shell) |
| MAL-009 | `malware_reference` | **Critical** | 40+ known malware family names |
| MAL-010 | `c2_communication` | High | Suspicious IP:port C2 URLs |
| MAL-011 | `c2_communication` | High | Hex shellcode sequences (`\x41\x42...`) |

---

### Stage 0.5 — Heuristic Rules (Signature-Less Detection)
| Rule | Category | Severity | What it Detects |
|---|---|---|---|
| HEUR-001 | `heuristic_malware` | High / Medium | Shannon entropy > 7.2 (packed/encrypted/obfuscated file) |
| HEUR-002 | `heuristic_malware` | High | >70% non-printable bytes in text-expected file type |
| HEUR-003 | `heuristic_malware` | High | Process injection APIs (`CreateRemoteThread`, `VirtualAllocEx`, `WriteProcessMemory`…) |
| HEUR-004 | `heuristic_malware` | **Critical** | Script downloader / LOLBIN strings (`powershell -enc`, `IEX`, `certutil -decode`…) |
| HEUR-005 | `heuristic_malware` | **Critical** | Valid embedded PE (MZ+PE sig) past byte 512 — polyglot/dropper |
| HEUR-006 | `heuristic_malware` | High | Packer section names (`.UPX0`, `.aspack`, `.themida`, `.MPRESS1`…) |
| HEUR-007 | `heuristic_malware` | High | MIME type / file extension mismatch (requires `python-magic`) |
| HEUR-008 | `heuristic_malware` | High | Dense base64 block ≥80 chars with entropy ≥4.5 (encoded payload) |

> **Disable heuristics:** Set `ENABLE_HEURISTICS=false` in `.env` to skip Stage 0.5 entirely.
> **Optional dependencies:** `pip install python-magic pefile` to enable HEUR-007 (MIME detection) and enhanced HEUR-003 PE import analysis.

---

## ⚡ Quick Start & Local Setup


### Option A: Local Native Execution (Fastest)

**Prerequisites:** Python 3.12+, Node.js 20+

```bash
# 1. Clone repository
git clone https://github.com/sandysunny99/aegis-node.git
cd aegis-node

# 2. Configure Environment
cp .env.example .env
# Edit .env and set your GEMINI_API_KEY (optional) and CLAMAV_MOCK_MODE=true

# 3. Backend Setup
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux / macOS
pip install -r ..\requirements.txt

# Start backend server
python -m uvicorn main:app --reload --port 8000
```

Open: **`http://localhost:8000`** (FastAPI serves both static React frontend and REST API).

---

### Option B: Docker Compose Stack (With ClamAV Antivirus)

```bash
# 1. Configure environment
cp .env.example .env

# 2. Start services (ClamAV sidecar + Aegis App container)
docker compose up -d --build

# 3. Monitor container readiness
docker compose logs -f app
```

Open: **`http://localhost`** (Nginx container) or **`http://localhost:8000`** (FastAPI container).

> **Note:** On first startup, ClamAV downloads its daily virus signature database (~250MB), which takes 2–3 minutes. The backend operates immediately with `CLAMAV_MOCK_MODE=true` or falls back to rule-based scanning until ClamAV reports healthy.

---

## 🔑 AI Provider Setup

Aegis Node provides intelligent AI threat advisories while preserving data privacy (only compact threat evidence metadata is sent to AI, never raw user dataset cells).

| Provider | Model | Setup Instructions |
|----------|-------|--------------------|
| **Google Gemini** | `gemini-flash-latest` | Obtain a free key at [Google AI Studio](https://aistudio.google.com/) |
| **Groq Cloud** | `llama-3.1-8b-instant` | Obtain a free key at [Groq Console](https://console.groq.com/) |
| **Ollama** | `llama3.1` (Local) | Install from [ollama.com](https://ollama.com) & run `ollama pull llama3.1` |
| **Rule Engine** | Deterministic Fallback | Active automatically when no key is set or upon provider quota limit |

Configure in `.env`:
```env
AI_PROVIDER=gemini
GEMINI_API_KEY=<YOUR_GEMINI_API_KEY>
GEMINI_MODEL=gemini-flash-latest
```

---

## ☁️ Cloud Deployment (Render.com)

Aegis Node features a native `render.yaml` Blueprint for 1-click cloud deployment:

1. Push code to GitHub repository.
2. Navigate to [dashboard.render.com](https://dashboard.render.com) → **New** → **Blueprint**.
3. Select `sandysunny99/aegis-node`.
4. Render auto-detects `render.yaml` and builds the single multi-stage container.
5. Set `GEMINI_API_KEY` under Environment variables.
6. Click **Deploy**.

---

## 🧪 Verification & Testing Suite

Execute the complete 133-test automated suite:

```bash
# Run complete test suite
python -m pytest tests/ -v --tb=short

# Run specific domain test modules
python -m pytest tests/test_scanner.py -v         # Core scanner & engine
python -m pytest tests/test_sanitizer.py -v       # Cell sanitization rules
python -m pytest tests/test_security.py -v        # Security & AI output validators
python -m pytest tests/test_remediation.py -v     # Single-use download token & path traversal
```

---

## 🛡️ Security Audit Compliance

The platform underwent a comprehensive 38-finding security audit across backend, frontend, scanner, and deployment layers:

- **Path Traversal Shield:** All files stored as UUIDs; strictly validated against root storage directories.
- **Single-Use Download Tokens:** Sanitized datasets require a single-use token expiring in 60 minutes with `secrets.compare_digest` validation.
- **Memory Bomb Defense:** Uploads stream in 1MB chunks enforcing max file size bounds before memory allocation.
- **Prompt Injection Neutralization:** Evidence inputs to AI models undergo strict validation and stripping of prompt manipulation keywords.
- **SQLite Concurrency:** Connection listener applies `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` on engine creation.

---

## 📂 Repository Structure

```
Aegis-Node/
├── backend/
│   ├── main.py                     # FastAPI app, CORS, /health endpoint
│   ├── config.py                   # Pydantic Settings with root .env resolution
│   ├── database.py                 # SQLite WAL connection engine
│   ├── models.py                   # Database schema definitions
│   ├── schemas.py                  # Pydantic request/response models
│   ├── routers/
│   │   ├── datasets.py             # Upload & scan API endpoints
│   │   ├── analysis.py             # AI analysis routing
│   │   ├── remediation.py          # Sanitization & single-use token downloads
│   │   └── history.py              # Scan history API
│   └── services/
│       ├── file_service.py         # Magic byte validation & file storage
│       └── llm_service.py          # AI provider dispatch & deterministic fallback
├── scanner/
│   ├── clamd_client.py             # TCP INSTREAM & Dev Mock ClamAV client
│   ├── content_checker.py          # Deobfuscation & regex rule engine
│   ├── engine.py                   # Two-stage scanner orchestrator
│   └── sanitizer.py               # In-place dataset cell neutralization
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # React 18 SPA root & header indicators
│   │   ├── api.js                  # Axios/XHR API client
│   │   └── components/
│   │       ├── UploadZone.jsx      # Progress bar drag-and-drop upload
│   │       ├── FindingsList.jsx    # Categorized threat findings
│   │       ├── RemediationCard.jsx # Threat reduction & download button
│   │       └── AiSummary.jsx       # AI Threat Advisory panel
├── docs/
│   ├── architecture.md             # System architecture & data flow
│   ├── audit_report.md             # 38 Audit findings & resolution log
│   └── final-defense-checklist.md # Production readiness checklist
├── Dockerfile                      # Multi-stage production build
├── docker-compose.yml              # Local multi-container stack
├── render.yaml                     # Render.com Cloud Blueprint
└── requirements.txt                # Python dependencies
```

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for details.

*Aegis Node © 2026 — Dataset Threat Detection & Automated Remediation Framework*
