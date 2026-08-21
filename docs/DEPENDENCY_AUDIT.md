# Aegis Node — Dependency Audit & Vulnerability Assessment

**Date**: August 2026  
**Auditor**: Senior Application Security Engineer & DevOps Engineer  
**Scope**: Backend (`requirements.txt`) and Frontend (`package.json`, `package-lock.json`)  

---

## 1. Frontend Dependency Audit

Command: `npm audit` (executed in `frontend/`)
- **Vulnerabilities Found**: 0
- **Total Packages Audited**: 147 dependencies
- **Framework**: React 18, Vite 5, TailwindCSS 3, Lucide React
- **Status**: **PASS (0 vulnerabilities)**

---

## 2. Backend Dependency Audit

| Package | Pinned Constraint | Purpose | Vulnerability Check | Action / Assessment |
|---|---|---|---|---|
| `fastapi` | `>=0.115.0` | Core ASGI API framework | None reported | Secure. Uses Starlette security middleware. |
| `uvicorn` | `>=0.30.0` | ASGI production server | None reported | Secure. Standard production runner. |
| `python-multipart` | `>=0.0.12` | Form/Multipart parser | Safe version pinned | `0.0.12` addresses previous boundary vulnerability. |
| `aiofiles` | `>=23.2.0` | Async file operations | None reported | Used for StaticFiles SPA serving. |
| `slowapi` | `>=0.1.9` | Per-IP rate limiting | None reported | Prevents brute force / upload flooding. |
| `pandas` | `>=2.2.0` | Tabular data manipulation | None reported | Memory limits enforced via chunking. |
| `pyarrow` | `>=16.0.0` | Parquet file parser | None reported | Secure batch iteration. |
| `openpyxl` | `>=3.1.0` | Excel spreadsheet parser | None reported | Uses `read_only=True` mode to mitigate XML entity bombs. |
| `sqlalchemy` | `>=2.0.31` | SQLite ORM & query builder | None reported | Parameterized queries prevent SQL injection. |
| `pydantic` | `>=2.7.0` | Schema validation | None reported | Enforces strict type casting and output bounds. |
| `google-genai` | `>=1.0.0` | Official Google Gemini SDK | None reported | Up-to-date SDK. |
| `httpx` | `>=0.27.0` | HTTP client (Groq, xAI) | None reported | TLS certificate verification enabled by default. |
| `python-magic` | `==0.4.27` | Content-based MIME detection | None reported | Safe fallback to extension-based guess if libmagic missing. |

---

## 3. Dependency Minimization Assessment

Aegis Node maintains a strictly minimal dependency footprint:
- **No Heavy Distributed Brokers**: Zero instances of Kafka, Celery, Redis, Elasticsearch, or Qdrant.
- **No Unused ML Frameworks**: No Torch/TensorFlow/Scikit-Learn dependencies installed without justification.
- **Standardized Lightweight Architecture**: The entire runtime runs within standard container constraints (<250MB image footprint).
