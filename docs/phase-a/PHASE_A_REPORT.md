# Phase A report: verify the existing pipeline

## 1. Branch, start commit, end commit
- Worked in a separate detached worktree at `C:\Users\sunny\Downloads\projects\AI FULL STACK PROJECT\aegis-phaseA-c895a6b`. The main checkout (`feat/bastion-frontend`, used by the audit thread) was not touched.
- Start = end = `c895a6b` ("fix: remove browser API key exposure", 13 Oct 2026). Nothing committed. The three docs are uncommitted files in that worktree.
- `c895a6b` was not in the local repo until `git fetch origin`. It exists only on `origin/sandysunny99-clamav-pipeline-verification` (4 commits on top of `main`: ClamAV REST validation, storage paths, frontend lint and download, browser API key).
- `fix/audit-2026-10` (20 commits on `main`, unpushed) and `feat/bastion-frontend` (audit + 3 docs commits) do **not** contain `c895a6b`, and `c895a6b` contains none of the audit fixes: TI opt-in defaults, scan state machine and quarantine re-scans, unguessable dataset ids, no token from GET, trusted-proxy IP, guardrail-bypass fix, path containment, provider-list rate limit. Both lines changed `config.py`, `file_service.py`, `storage.py` and `api.js`, so they will conflict when merged.

## 2. What was verified
| Check | Command | Result |
|---|---|---|
| Git state | `git status`, `branch -a -vv`, `log -15`, `remote -v`, `fetch origin`, `branch -a --contains c895a6b` | as above |
| Backend tests | `.venv\Scripts\python.exe -m pytest -q` (PowerShell, in the worktree, no `.env`) | **363 passed**, 1 warning, 99 s. Not 286 (the prompt's figure is older). |
| Frontend lint | `npm ci` then `npm run lint` (eslint, `--max-warnings 0`) | clean |
| Frontend build | `npm run build` (vite 6.4.3) | built, JS 184.8 kB (55.9 kB gzip) |
| E2E with Docker | `docker ps` | **not run**: Docker Desktop daemon not running |
| E2E without Docker | local uvicorn on the worktree, ClamAV URL unreachable, all outbound HTTP to a dead local proxy, script in session scratchpad | a, b, c, d, e run; results below |

E2E results (HTTP 201 upload, 200 scan, 200 report in every case):
- **a) harmless CSV**: `clean_with_limitations` (ClamAV unavailable, plus a false `PARTIAL_DATASET_SCAN` 4/5 rows, gap #4). Stored status `clean`.
- **b) EICAR** (built in memory, saved by the app under a scratch DATA_DIR, deleted afterwards): `malicious`, risk 9.0, MAL-001 ×2 + YARA-002, file quarantined. Remediation `completed`, download had no EICAR, second download 403, GET remediation returns no token. Re-scan of the original → 409, then status became `error` (gap #2).
- **c) formula injection fixture**: `suspicious`, FORM-001 + FORM-003, remediated `completed`, 4 cells changed.
- **d) provider down** (TI enabled with dummy keys, network dead): `clean_with_limitations`, TI `status=error`, `PROVIDER_UNAVAILABLE`, every provider listed as unavailable. Not reported as clean_verified. Stored status still `clean` (gap #1).
- **e) remediation + re-scan**: covered in b and c. Re-scan ran with ClamAV unreachable and still counted as `completed` (gap #3).
- Extra, malformed JSON: `scan_incomplete`, stored status `clean` (gap #1).
- What the UI would show for these: per `INTEGRATION_GAPS.md` #5–#7, the TI card shows "0 malicious / no match" in every case, limitations are never shown, and the remediation card would show "Dataset is Clean" for the malformed and provider-down scans.

## 3. Changes
- `docs/PIPELINE_MAP.md` (new, uncommitted): stages, modules, statuses, flags, failure behaviour, tests; detector inventory.
- `docs/INTEGRATION_GAPS.md` (new, uncommitted): 24 numbered gaps with severity.
- `docs/PHASE_A_REPORT.md` (this file).
- No code changed.

## 4. New dependencies
None. `npm ci` restored the locked frontend packages inside the worktree only.

## 5. Benchmark before/after
Not run (Phase A has no change to measure).

## 6. Open gaps, risks and decisions
1. **Baseline for `feat/detection-layers`.** Cutting it from `c895a6b` leaves out every audit security fix; cutting it from `fix/audit-2026-10` leaves out the 4 ClamAV / storage commits. Options: cut from `c895a6b` and cherry-pick the audit fixes later; cut from the audit branch and cherry-pick the 4 commits; or merge the two first.
2. **Four defects in the frozen core** (`INTEGRATION_GAPS.md` #1–#4). #2 is already fixed on the audit branch. #1 adds status values, which the prompt treats as a frozen-core change. Each needs your yes before a failing test and fix.
3. **The UI does not show threat intel or limitations truthfully** (#5–#7). These belong to the Bastion P0 work on `feat/bastion-frontend`, not Phase B.
4. Docker E2E (real ClamAV, real EICAR detection by ClamAV) is still unproven. It needs Docker Desktop started.
5. MetaDefender uploads whole files when selected (#17); it should probably be removed or made hash-only before the detection-layer work.

PHASE A BLOCKED: Docker end-to-end not run (daemon down), and four frozen-core defects plus the baseline choice need your decision.
