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
and host security protection should remain enabled. Artifacts use the
`aegis_node_artifacts` volume at `/app/data` and SQLite uses `aegis_node_db` at `/app/db`. Do not send the EICAR fixture to public threat
intelligence services (for example, VirusTotal).

Docker Compose stores uploaded/sanitized artifacts on the `aegis_node_artifacts` named
volume (`/app/data`) and the SQLite database on `aegis_node_db` (`/app/db`). Named volumes
live inside the Docker VM, so Windows Defender cannot rewrite EICAR/malware samples the way
it does on a `./data` bind mount, and data survives container restarts (unlike tmpfs). The Render free-tier blueprint uses ephemeral `/tmp` storage;
use a persistent disk and point `DATABASE_URL` and `DATA_DIR` at that disk for durable production data.

### Stopping the local stack

`.\scripts\cleanup.ps1` runs `docker compose down` and keeps every volume (scan history,
artifacts, ClamAV database). `-DryRun` shows what it would do. `-StopListeners` offers to stop
python/uvicorn/node dev servers on ports 8000 and 5173, one confirmation per process.
Deleting the Aegis volumes is a separate step: `-RemoveVolumes` lists the volumes and asks
you to type `DELETE AEGIS DATA`; without a console it is refused unless
`-ConfirmDeletion "DELETE AEGIS DATA"` is passed.

### Migrating an existing local `./data` directory

The Compose configuration uses named volumes (`aegis_node_artifacts` for artifacts, `aegis_node_db` for
SQLite) so the non-root container can write them reliably. If an older installation used `./data:/app/data`, the
host directory is not copied automatically: the named volume masks it at `/app/data`. Before
switching, stop the application and make a separate backup of `./data`. After reviewing that
backup, copy its contents into the named volume with Docker Desktop running:

```powershell
docker compose stop app
docker run --rm `
  -v "${PWD}\data:/from:ro" `
  -v aegis_node_artifacts:/to `
  alpine sh -c "cp -a /from/. /to/"
docker compose up -d app
```

Only perform this copy when the named volume is the intended destination and its existing
contents have been backed up; it can overwrite files with matching names. Do not use
`down -v`, `docker volume rm`, or another destructive volume command as part of migration.
Render's `/tmp/aegis_data` and `/tmp/aegis_node.db` remain ephemeral unless persistent storage is
configured separately. Application-container recreation has been verified against the named
volume; recovery after Docker-volume loss or host failure requires a separate backup/restore
drill and is not implied by that persistence check.

The server-side `API_KEY` is a privileged machine-client credential and is never exposed through
the Vite frontend. The browser client does not read or embed `VITE_API_KEY`; if `API_KEY` is
enabled for a deployment, browser write access requires a separately authenticated gateway or
user-session design. Do not place a production API key in any `VITE_*` variable, because Vite
embeds those values in public browser assets.

## Documentation

All project documents are indexed in [docs/README.md](docs/README.md). The current security
state and fix log is [docs/AUDIT_2026-10.md](docs/AUDIT_2026-10.md).
