# Aegis Node: Developer Guide

## Repository Structure
- `/backend`: FastAPI application, endpoints, and business logic.
  - `/services`: Core logic (AI, Threat Intelligence, Storage, Guardrails).
  - `/routers`: API endpoints.
- `/frontend`: React + Vite application.
- `/tests`: Pytest suite for backend validation.
- `/docs`: Architecture and release documentation.

## Local Development
1. **Backend:**
   - `python -m venv venv && source venv/bin/activate`
   - `pip install -r requirements.txt`
   - `uvicorn backend.main:app --reload`
2. **Frontend:**
   - `cd frontend`
   - `npm install`
   - `npm run dev`

## Regression & Testing
Run the following commands to ensure system integrity:
```bash
python -m pytest tests/ -v
pip check
npm audit
git diff --check
cd frontend && npm run build
```

## Security-Sensitive Boundaries
When modifying the codebase, preserve the following invariants:
1. **Never execute uploaded content.**
2. **Do not fetch or probe attacker infrastructure** (keep TI lookup-only).
3. **Always evaluate AI guardrails** before invoking `llm_service`.
4. **Never allow LLMs to override deterministic verdicts.**
