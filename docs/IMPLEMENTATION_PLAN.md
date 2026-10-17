# Implementation plan: accuracy, history, sandbox, provider gate

Written 17 Oct 2026 for the "master implementation instructions". Updated as each gate closes.

## Gate 1: baseline (verified with Git, 17 Oct 2026)

| Item | State |
|---|---|
| Working branch | `integrate/core-audit` in worktree `aegis-integrate`, clean, head `f9e2ca5` |
| Earlier report of `9fd35e9` | Not a conflict: `9fd35e9` is the deploy commit, `f9e2ca5` the docs commit on top of it |
| Tags (local only) | `core-baseline-v2` → `9f473b0`; `core-freeze-2026-10-13` → `c895a6b` |
| `feat/detection-layers` | `9f473b0` (= `core-baseline-v2`), no commits yet |
| `feat/bastion-frontend` | `2ca2257`, checked out in the main worktree by the UI thread; contains `core-baseline-v2` (merged twice, as recorded there); 13 commits not on `integrate/core-audit`; it also changes `backend/main.py` (gzip), which will need care when the branches meet |
| Commits on `integrate/core-audit` not on Bastion | `d7d1fc2` (profiles, `/health/detectors`, gateway client), `9fd35e9` (Oracle deploy), `f9e2ca5` (provider docs) |
| Remote | `origin` = github.com/sandysunny99/aegis-node; nothing from this work is pushed |
| Tests before editing | backend `484 passed` (89.9 s, PowerShell, isolated `.env`-free worktree); frontend lint 0 warnings; build OK |

## Phase A findings

| # | Type | Where | Finding | Fix / regression test |
|---|---|---|---|---|
| A1 | Confirmed defect | `scanner/content_checker.py: raw_bytes_scan` | Any `MZ` pair after byte 512 is reported as an embedded PE (MAL-002 high), so ordinary datasets become `suspicious` | Validate DOS header, bounded `e_lfanew`, `PE\0\0`; separate `possible_executable_marker` from `validated_embedded_pe` (B1) |
| A2 | Confirmed defect | `content_checker._load_dataframe` (xlsx) | `rows_total = len(df)` after reading at most 10,000 rows, so coverage says FULL for larger workbooks; only the first sheet is read | Count rows per sheet from the workbook dimensions, report PARTIAL with the limit hit (B2) |
| A3 | Confirmed defect | `threat_intelligence/enrichment.py:_url_evidence` | URLhaus `not_found` → `benign` | Map to `unknown` / NO_MATCH (B3) |
| A4 | Detection-quality risk | `enrichment.py` | TI outage leaves `clean_verified` with limitations mixed into the same list | Separate `enrichment_status` (Phase H) |
| A5 | Missing capability | `models.py`, `routers/history.py` | History is "latest scan per dataset" only; no per-scan events, no scan detail route, no filters | Event model and routes (Phase C) |
| A6 | Missing capability | `requirements.txt` | No PostgreSQL driver, so `DATABASE_URL=postgresql://…` (Neon) cannot work today; history is durable only where SQLite sits on a volume (local Docker) | Decision needed: add `psycopg[binary]` (LGPL-3.0) or stay on SQLite |
| A7 | Security risk (low) | scanner, sanitizer | No `eval`/`exec`/`subprocess`/`pickle` on uploaded content (grep); parsing runs in the web process with only row/size caps | Bounded parsing + zip-bomb guard; sandbox design (Phase D) |
| A8 | Detection-quality risk | `main.py` `/health` | AV status cached up to 5 minutes | Documented; `/health/detectors` shares the cache |
| A9 | Documentation gap | `docs/` | No single verdict/status truth table | `docs/architecture/VERDICT_TRUTH_TABLE.md` |
| A10 | Not reproducible / needs evidence | abuse.ch | Official pages did not resolve on 17 Oct 2026 | Recheck at Gate 4 |

Frontend (`integrate/core-audit` still has the old UI): it reads `/health` only and shows hard-coded "YARA: Enabled"; the redesigned UI lives on `feat/bastion-frontend` and is out of scope for this thread except for the history API contract.

## Order of work

1. B1 MZ false positive → 2. B2 XLSX coverage → 3. B3 URLhaus mapping + truth table + enrichment status → 4. Scan history events and API (contract posted for the UI thread) → 5. Static-analysis safeguards and sandbox design → 6. Gate 4: recheck abuse.ch, stop for provider approval.

Not in this thread: Bastion UI changes (History page), any push or deploy, Oracle VM creation, Render configuration changes.
