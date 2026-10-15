# Architectural Decisions
- **ADR-001**: Use FastAPI and SQLite for a lightweight, deployable runtime.
- **ADR-002**: Local Detection First. ClamAV and YARA provide ground truth; LLM provides context, not primary detection.
- **ADR-003**: No AGPL dependencies in runtime. OpenViking ideas used for context only.
- **ADR-004**: Render Free Tier compatibility requires ephemeral SQLite (/tmp) instead of persistent disks.

## Bastion frontend redesign (branch feat/bastion-frontend)
- **2026-10-15, merge**: merged local tag `core-baseline-v2` (571e5d4: fix/audit-2026-10 + c895a6b + 7 core fixes) into feat/bastion-frontend before any P1 work, so the UI is built against the final status and threat-intel shapes. Result: 458 tests pass, ruff clean, frontend lint and build pass. Not pushed.
- **2026-10-15, status defaults**: `clean_limited` → degraded "Clean, limited scan"; `incomplete` → degraded "Scan incomplete"; `remediated_unverified` → degraded "Remediation unverified". Why: a scan or clean-up that could not be fully verified must never look healthy. Defaults pending Sandeep's confirmation; the full map is in DESIGN.md.
- **2026-10-15, re-merge**: `core-baseline-v2` moved to 9f473b0 (Dockerfile creates `/app/db` so the compose SQLite volume is writable); merged again as 920549f. 458 tests pass, ruff clean, `docker compose config` valid. Not pushed.
