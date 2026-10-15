# Merge notes: integrate/core-audit

`integrate/core-audit` was created from `fix/audit-2026-10` (722c477). It merges `origin/sandysunny99-clamav-pipeline-verification` (c895a6b, tagged locally as `core-freeze-2026-10-13`) with `git merge --no-ff`, so both histories are kept.

Rule applied: the audit branch's security behaviour wins, and c895a6b's ClamAV REST validation, storage-path, frontend lint/download and browser-API-key fixes are kept. Where both sides changed the same logic, the result combines them.

## Conflicted hunks

| File | Hunk | Resolution | Why |
|---|---|---|---|
| `backend/config.py` | Database / data dir | Audit's empty `DATABASE_URL` default (SQLite under `DATA_DIR`, CWD-independent) **plus** c895a6b's `resolve_data_dir` validator (relative `DATA_DIR` resolves from the repo root) | Both fixes address path drift; they don't overlap |
| `backend/config.py` | `trusted_proxies` error | Audit (`from exc`) | Ruff-clean form from the audit |
| `backend/config.py` | Trailing blank lines | c895a6b | Whitespace only |
| `backend/services/storage.py` | `get_storage_backend` | Audit's shared `get_data_directory()` helper, but **without** its silent `/tmp/aegis_data` fallback: an uncreatable `DATA_DIR` now raises | c895a6b's test `test_configured_data_directory_permission_error_is_not_hidden` states the intent: artifacts must not move silently to a path that doesn't persist |
| `backend/services/file_service.py` | Imports, `_BASE_DATA_DIR`, two log calls | Audit (`get_data_directory()`, %-style logging) | Same behaviour as c895a6b once the helper no longer falls back |
| `backend/services/av_providers/clamav.py` | `from typing import Any` | c895a6b | Needed by c895a6b's `_extract_version`; the rest of its ClamAV REST validation merged cleanly |
| `tests/test_storage.py` | Imports | Both (`Path`, `get_data_directory`, `get_storage_backend`) | Both sides' tests kept |
| `docker-compose.yml` | App volumes | Audit: artifacts on `aegis_node_artifacts` at `/app/data`, SQLite on `aegis_node_db` at `/app/db` | Both sides use named volumes for persistence and Defender safety; the audit splits DB from artifacts |
| `frontend/eslint.config.js` | Ignores and globals | Audit (`dist/**`, `node_modules/**`, `globals.browser`) | Superset of c895a6b's hand-listed globals; lint passes |
| `frontend/src/api.js` | API-key comment, 401 text, download headers | Audit | Both sides removed the browser API key; the audit's 401 text explains it truthfully |
| `frontend/src/components/TurnstileWidget.jsx` | Cleanup catch | Audit (logs a warning) | Errors are not swallowed silently |
| `frontend/src/App.jsx` | Trailing blank line | c895a6b | Whitespace only |
| `.env.example` | Database block | Audit block (empty `DATABASE_URL`, TI opt-in switches off) plus c895a6b's comment on how `DATA_DIR` resolves | Keeps the privacy defaults and the path explanation |
| `README.md` | Docker / storage section | Both: audit's volume description and docs index, c895a6b's migration steps and API-key note. Volume names in c895a6b's text corrected to the audit's split (`aegis_node_artifacts` / `aegis_node_db`) | The c895a6b text described the single-volume layout that the merge no longer uses |

Auto-merged without conflict from c895a6b: ClamAV REST response validation and tests (`tests/test_clamav_rest_provider.py`), Dockerfile, the PowerShell validation scripts, and frontend component lint fixes.

## Verification after the merge
- Backend: `python -m pytest -q` → **422 passed** (audit branch alone: 402; c895a6b alone: 363).
- `ruff check .` → all checks passed.
- Frontend: `npm ci`, `npm run lint` (0 warnings), `npm run build` → built.
