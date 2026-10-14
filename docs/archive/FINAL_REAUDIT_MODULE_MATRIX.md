# Final Re-Audit: Module Matrix

| Module | Purpose | Security Assumptions | External Deps | Known Weaknesses | Recommendation |
|--------|---------|----------------------|---------------|------------------|----------------|
| `backend/main.py` | Entrypoint | Trusted CORS boundaries | None | None | PASS |
| `backend/config.py` | Config load | Environment variables are safe | None | None | PASS |
| `backend/database.py` | DB init | DB is isolated | SQLAlchemy | SQLite lock risks under load | Consider Postgres for scale |
| `backend/routers/upload.py` | Upload | Strictly validates MIME/Ext | None | None | PASS |
| `backend/services/scanner/` | Scanning | ClamAV reachable | clamd | ClamAV dependency | PASS |
| `backend/services/threat_intelligence/` | TI Fusion | Lookup-only | URLhaus/AbuseIPDB | Network failure | PASS |
| `backend/services/guardrails.py` | Guardrails| Predictable PI | None | 80% holdout | PASS (contained) |
| `backend/services/llm_service.py` | LLM | Zero authority | Cloudflare GW | Hallucination | PASS (contained) |
| `backend/routers/remediation.py`| Remediation| Safe file output | pandas | Binary unsupported | PASS (limited) |
