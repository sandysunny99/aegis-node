# Aegis Node

Aegis Node is a full-stack security application designed to scan, analyze, and remediate datasets. It enforces strict defense-in-depth principles, isolating untrusted data and bounding all external interactions.

## Project Overview
Aegis Node evaluates datasets through deterministic scanning, threat intelligence enrichment, and AI-assisted analysis, bounded by native prompt-injection guardrails.

## Key Capabilities
- Deterministic malware and heuristic scanning.
- Threat Intelligence fusion (URLhaus, AbuseIPDB).
- Bounded AI analysis via Cloudflare AI Gateway.
- Automated remediation and verified sanitization.

## Quick Start
```bash
# Backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn backend.main:app --reload

# Frontend
cd frontend
npm install
npm run dev
```

## Deployment Overview
- **Frontend:** Vercel
- **Backend:** Render (Docker)
- **AI Gateway:** Cloudflare

## Security Model
**The system does not trust any single security layer.** Deterministic scans dictate verdicts; AI assists contextually. All external TI lookups are strictly bounded to prevent SSRF. See `docs/AEGIS_NODE_SECURITY_ARCHITECTURE.md`.

## Testing
Run the regression suite: `python -m pytest tests/ -v`

## Release Status & Limitations
**RELEASE READY WITH DOCUMENTED LIMITATIONS.**
Please review `docs/LIMITATIONS.md` for information regarding guardrail holdout metrics (80% / 20%), TI coverage limits, and binary remediation boundaries.
