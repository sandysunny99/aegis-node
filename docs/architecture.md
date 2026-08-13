# 🏛️ Aegis Node — Architectural Specification & Threat Model

This document outlines the system architecture, threat model, data flows, scanning engine design, and security controls of **Aegis Node**.

---

## 1. System Overview & Key Subsystems

Aegis Node consists of five decoupled core subsystems:

```
┌──────────────────────────────────────────────────────────────────────────┐
│                            1. UI Subsystem                               │
│  React 18 + Vite SPA, Chakra UI / Custom CSS, Real-time XHR Progress      │
└────────────────────────────────────┬─────────────────────────────────────┘
                                     │ HTTP REST API
                                     ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                         2. API & Control Layer                           │
│  FastAPI (Python 3.12), SlowAPI Rate Limiting, Magic-Byte Inspection     │
└──────────────┬─────────────────────┬──────────────────────┬──────────────┘
               │                     │                      │
               ▼                     ▼                      ▼
┌──────────────────────────┐ ┌───────────────┐ ┌──────────────────────────┐
│   3. Scanning Pipeline   │ │ 4. Sanitizer  │ │   5. AI Advisory Router  │
│  • ClamAV INSTREAM Client│ │   Neutralizes │ │  • Gemini (Flash Latest) │
│  • Deobfuscator Engine   │ │   malicious   │ │  • Groq (Llama 3.1)      │
│  • Regex Rule Matching   │ │   cell text   │ │  • Ollama (Local LLM)    │
└──────────────────────────┘ └───────────────┘ └──────────────────────────┘
```

---

## 2. Scanning & Remediation Engine Design

### Stage 1: Antivirus Stream Check (ClamAV)
Files are streamed to ClamAV over TCP port 3310 using the `zINSTREAM` protocol in 4KB chunks. When running natively without Docker Desktop, `CLAMAV_MOCK_MODE=true` enables local development mock responses (`stream: OK`).

### Stage 2: Content Deobfuscation
Prior to rule matching, cell values undergo recursive deobfuscation:
1. **URL Decoding:** Replaces `%27`, `%22`, `%3Cscript%3E`, etc.
2. **HTML Entity Unescaping:** Resolves `&lt;`, `&gt;`, `&#x27;`.
3. **SQL Comment Strip:** Removes `/* ... */` inline comments used to bypass regex rules.
4. **Whitespace Normalization:** Collapses multiple spaces and tab characters.

### Stage 3: Regex Rule Matching (9 Rule Definitions)
Matching is performed against deobfuscated tokens:
- **RULE-CSV-001 (Formula Injection):** Identifies prefix `=`, `@`, `+`, `-`, `DDE`, `HYPERLINK`.
- **RULE-SQL-001 (SQL Injection):** Identifies `OR 1=1`, `UNION SELECT`, `DROP TABLE`, `INSERT INTO`.
- **RULE-SCRIPT-001 (Script/XSS Injection):** Identifies `<script>`, `javascript:`, `eval()`, `onerror=`.
- **RULE-NULL-001 (Null Byte Injection):** Identifies `\x00` characters.

### Stage 4: Risk-Based Cell Sanitization
Sanitization preserves schema and non-malicious cell data:
- **Formula Neutralization:** Prepends single-quote `'` to formula triggers (e.g. `=SUM(A1)` → `'=SUM(A1)`).
- **SQL / Script Neutralization:** Neutralizes or strips script and SQL constructs.
- **Null Byte Stripping:** Eliminates binary null bytes.

---

## 3. Threat Model & Defense-in-Depth

| Threat | Potential Impact | Aegis Node Defense Mechanism |
|--------|------------------|──────────────────────────────|
| **Path Traversal Attack** | Arbitrary file read/write | File names mapped to randomly generated UUIDs. Strict directory boundary checks enforced in `file_service.py`. |
| **Server-Side Request Forgery (SSRF)** | Internal network scan | Input dataset URLs and external links are strictly rejected. Only direct file uploads accepted. |
| **Unbounded Memory Exhaustion** | Denial of Service (OOM) | Uploads stream in 1MB chunks. Maximum upload threshold configured via `MAX_UPLOAD_SIZE_MB`. |
| **Prompt Injection to LLM** | LLM hijack / unsafe advice | Raw cell data is NEVER passed to the LLM. Only compact metadata evidence (rule ID, column, row index, risk score) is submitted. System prompt explicitly marks evidence payload as untrusted input. |
| **Database Concurrency Deadlocks** | App lockup during writes | Database engine initialized with SQLite Write-Ahead Logging (`PRAGMA journal_mode=WAL`). |
| **Unauthorized File Downloads** | Data leakage | Downloads require single-use tokens expiring in 60 minutes with `secrets.compare_digest` validation and `Cache-Control: no-store` headers. |

---

## 4. Environment & Deployment Configurations

### Local Development (Native Python)
- **Backend:** `python -m uvicorn main:app --reload`
- **Frontend:** React Vite dev server (`npm run dev`)
- **Settings:** `.env` loaded via Pydantic `BaseSettings` with automatic root path resolution.

### Production Docker Container
- **Base Image:** `python:3.12-slim` + `node:20-alpine` (multi-stage build).
- **Process Manager:** `uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1`.
- **Static Hosting:** FastAPI mounts `/static` directory to serve the pre-built React SPA SPA routing handles client-side views.

---

*Aegis Node Architecture Documentation — 2026*
