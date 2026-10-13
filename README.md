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
- **Frontend:** Render
- **Backend:** Render (Docker)
- **AI Gateway:** Cloudflare

## Security Model
**The system does not trust any single security layer.** Deterministic scans dictate verdicts; AI assists contextually. All external TI lookups are strictly bounded to prevent SSRF. See `docs/AEGIS_NODE_SECURITY_ARCHITECTURE.md`.

## Testing
Run the regression suite: `python -m pytest tests/ -v`

## Release Status & Limitations
**RELEASE READY WITH DOCUMENTED LIMITATIONS.**
Please review `docs/LIMITATIONS.md` for information regarding guardrail holdout metrics (80% / 20%), TI coverage limits, and binary remediation boundaries.


## Local Docker Validation
To validate the local ClamAV integration on Windows, install and start **Docker Desktop**, then run
`.\scripts\final_runtime_validation.ps1` from PowerShell. The script starts the Compose `app`
service and its declared dependencies, waits for ClamAV REST and Aegis readiness, then submits a
harmless CSV and the standard EICAR test signature from memory through Aegis's upload and scan
endpoints. It fails unless Aegis reports an actual ClamAV clean result for the harmless file and a
ClamAV EICAR detection for the test signature. No EICAR file is written to the Windows filesystem,
and host security protection should remain enabled. Local SQLite and artifact data use the
`aegis_node_db` Docker volume mounted at `/app/data`. Do not send the EICAR fixture to public threat
intelligence services (for example, VirusTotal).

### Migrating an existing local `./data` directory

The Compose configuration uses the named `aegis_node_db` volume so the non-root container can
write SQLite and artifact data reliably. If an older installation used `./data:/app/data`, the
host directory is not copied automatically: the named volume masks it at `/app/data`. Before
switching, stop the application and make a separate backup of `./data`. After reviewing that
backup, copy its contents into the named volume with Docker Desktop running:

```powershell
docker compose stop app
docker run --rm `
  -v "${PWD}\data:/from:ro" `
  -v aegis_node_db:/to `
  alpine sh -c "cp -a /from/. /to/"
docker compose up -d app
```

Only perform this copy when the named volume is the intended destination and its existing
contents have been backed up; it can overwrite files with matching names. Do not use
`down -v`, `docker volume rm`, or another destructive volume command as part of migration.
Render's `/tmp/aegis_data` and `/tmp/aegis_node.db` remain ephemeral unless persistent storage is
configured separately.
