# 🛡️ Aegis Node — Dataset Threat Detection & Remediation

An M.Tech mini-project web application that scans datasets for malware and injection threats, explains them using AI, and automatically cleans the dataset.

---

## 📌 Features

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-stage Scanning** | ClamAV antivirus + deobfuscation preprocessing + regex rule engine |
| ⚡ **Injection Detection** | Formula injection (=, @, DDE, HYPERLINK), SQL injection, Script/XSS injection, Null bytes |
| 🧹 **Deobfuscation** | URL decoding, HTML entity unescaping, SQL comment removal before matching |
| 🤖 **AI Threat Analysis** | Gemini / Groq (Llama 3.1) / Local Ollama — advisory explanation only |
| 🛠️ **Risk-Based Remediation** | In-place neutralization preserving dataset schema |
| ✅ **Verification Re-scan** | Automated re-scan of sanitized file with threat reduction % |
| 📊 **Format Support** | CSV, JSON, JSONL, Parquet, XLSX, TXT |
| 📋 **Scan History** | SQLite-backed history of all scans with download links |
| 🐳 **Docker Ready** | One-command startup with `docker compose up` |

---

## 🏗️ Architecture

```
Browser (React 18 + Vite)
        │
        ▼ REST API
FastAPI Backend (Python 3.12)
        │
        ├── Scanner Engine
        │   ├── ClamAV TCP Client (INSTREAM)
        │   ├── Deobfuscator (URL/HTML decode, SQL comment strip)
        │   └── Regex Rule Engine (9 rules)
        │
        ├── Sanitizer Engine (in-place neutralization)
        ├── Evidence Builder (no raw data sent to AI)
        └── AI Provider Router (Gemini / Groq / Ollama)
```

---

## ⚡ Quick Start

### Option A: Local Development (No Docker)

**Prerequisites:** Python 3.12, Node.js 20

```bash
# 1. Clone and enter project
cd Aegis-Node

# 2. Backend setup
cd backend
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r ..\requirements.txt

# 3. Configure environment
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY (optional)

# 4. Start backend
uvicorn main:app --reload --port 8000

# 5. Start frontend (new terminal)
cd ..\frontend
npm install
npm run dev
```

Open: **http://localhost:5173**

---

### Option B: Docker Compose (Recommended)

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env — add AI API key if desired

# 2. Start all services (ClamAV + Backend + Frontend)
docker compose up

# 3. Open application
# http://localhost  (Nginx frontend)
# http://localhost:8000/docs  (FastAPI Swagger UI)
```

> **Note:** ClamAV downloads its virus database on first start (~200MB). This takes 2–5 minutes. The backend starts immediately and falls back to rule-only scanning if ClamAV is not yet ready.

---

## 🔑 AI Configuration

| Provider | Cost | Setup |
|----------|------|-------|
| **Google Gemini** | Free tier | Get key at [aistudio.google.com](https://aistudio.google.com) |
| **Groq Cloud** | Free tier | Get key at [console.groq.com](https://console.groq.com) |
| **Ollama (local)** | 100% free | Install from [ollama.com](https://ollama.com), run `ollama pull llama3.1` |
| **None** | — | App works fully without AI (AI button hidden) |

Set in `.env`:
```env
AI_PROVIDER=gemini          # gemini | groq | ollama | none
GEMINI_API_KEY=your_key_here
```

---

## 🧪 Testing

```bash
# Run all tests
cd Aegis-Node
python -m pytest tests/ -v

# Run specific test files
python -m pytest tests/test_scanner_rules.py -v   # Detection rules
python -m pytest tests/test_sanitizer.py -v       # Sanitization logic
python -m pytest tests/test_api.py -v             # API endpoints
```

---

## 📁 Project Structure

```
Aegis-Node/
├── backend/
│   ├── main.py                     # FastAPI app + enhanced /health endpoint
│   ├── config.py                   # Settings (Gemini, Groq, Ollama, ClamAV)
│   ├── models.py                   # SQLite ORM models
│   ├── schemas.py                  # Pydantic API schemas
│   ├── database.py                 # DB session management
│   ├── routers/
│   │   ├── datasets.py             # Upload, scan, status endpoints
│   │   ├── analysis.py             # AI analysis endpoint
│   │   ├── remediation.py          # Sanitize + download endpoints
│   │   └── history.py              # Scan history endpoint
│   └── services/
│       ├── file_service.py         # UUID storage, SHA-256, path guards
│       ├── llm_service.py          # Multi-provider AI routing
│       └── ai_providers/
│           ├── groq_provider.py    # Groq Cloud (Llama 3.1)
│           └── ollama_provider.py  # Local Ollama
├── scanner/
│   ├── clamd_client.py             # ClamAV TCP INSTREAM client
│   ├── content_checker.py          # Deobfuscation + 9 regex rules
│   ├── engine.py                   # Two-stage scan orchestrator
│   └── sanitizer.py               # Risk-based cell neutralization
├── frontend/
│   ├── src/
│   │   ├── App.jsx                 # Main app with health status header
│   │   ├── api.js                  # XHR-based client with upload progress
│   │   ├── components/
│   │   │   ├── UploadZone.jsx      # Drag-drop with progress bar
│   │   │   ├── FindingsList.jsx    # Sortable threat findings table
│   │   │   ├── RemediationCard.jsx # Integrity rings + action log
│   │   │   ├── AiSummary.jsx       # AI advisory panel
│   │   │   ├── RiskMeter.jsx       # SVG arc risk gauge
│   │   │   └── StatusBadge.jsx     # Verdict chip
│   │   └── pages/
│   │       └── HistoryPage.jsx     # Paginated scan history
│   ├── Dockerfile                  # Multi-stage Nginx build
│   └── nginx.conf                  # API proxy + SPA routing
├── data/
│   ├── demo_malicious.csv          # 15-row dataset with injection vectors
│   ├── demo_clean.csv              # 15-row clean employee dataset
│   ├── samples/                    # Uploaded datasets (auto-created)
│   ├── quarantine/                 # High-risk files (auto-created)
│   └── sanitized/                  # Cleaned files (auto-created)
├── tests/
│   ├── conftest.py
│   ├── test_scanner_rules.py       # 30+ detection rule tests
│   ├── test_sanitizer.py           # Sanitization correctness tests
│   └── test_api.py                 # FastAPI endpoint tests
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## 🎯 Demo Flow (Live Presentation)

1. **Upload** `data/demo_malicious.csv` using drag-and-drop
2. **Observe** pipeline steps completing in real time
3. **Review** threat table — 3 types: SQL injection, formula injection, script injection
4. **Click** "Explain with AI" → see advisory analysis (if API key configured)
5. **Click** "Remediate & Sanitize" → watch integrity ring + threat reduction
6. **Download** clean dataset — verify threats removed
7. Upload `data/demo_clean.csv` → show zero false positives

---

## 🔐 Security Principles

- **No eval/exec** — All file content is read-only via pandas/openpyxl parsers
- **Path traversal protection** — UUID-named files, directory boundary checks
- **Data minimization** — Raw cell contents are NEVER sent to AI; only compact metadata
- **Prompt injection defense** — System prompt explicitly marks evidence as untrusted
- **Structured AI output** — All responses validated via Pydantic before use
- **Graceful fallback** — ClamAV offline → rule-only scan; AI unavailable → deterministic summary

---

## 📚 Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Vanilla CSS |
| Backend | Python 3.12, FastAPI, Uvicorn |
| Database | SQLite via SQLAlchemy 2.0 |
| Parsing | pandas, pyarrow, openpyxl |
| Antivirus | ClamAV (Docker, TCP INSTREAM) |
| AI | Google Gemini / Groq / Ollama |
| Testing | pytest, FastAPI TestClient |
| Deployment | Docker Compose, Nginx |

---

*Aegis Node © 2026 — M.Tech Mini Project — Secure Dataset Analysis Framework*
