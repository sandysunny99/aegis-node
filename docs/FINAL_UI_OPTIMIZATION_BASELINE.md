# Aegis Node UI Optimization Baseline

**Local HEAD:** `4e55a0c`
**Origin/Main HEAD:** 20 commits behind local (`1ac71d5...` or similar based on user description)
**Divergence:** Local branch is strictly ahead of origin/main by 20 commits representing Phases 9–13 (URLhaus, AbuseIPDB, TI Fusion, AI Guardrails, UI Observability, Validation, Cleanup).

**Architecture:**
- **Frontend:** React + Vite (Vercel deployment intended)
- **Backend:** FastAPI + SQLite (Render deployment intended)
- **Threat Intelligence:** VirusTotal (hash), URLhaus, AbuseIPDB
- **AI Modules:** Gemini (previous primary), Groq (new primary), Cloudflare AI Gateway, xAI, HuggingFace
- **Security Controls:** ClamAV, YARA, Heuristics, Normalization, TI Fusion, AI Guardrail (ALLOW/RESTRICT/BLOCK), Deterministic Remediation, Mandatory Verification.

*Note: Security logic is frozen and will not be modified.*
