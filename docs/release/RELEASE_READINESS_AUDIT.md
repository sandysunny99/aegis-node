# Release readiness audit

Release branch `release/2026-10-core-bastion`, candidate head `2045b7f` (plus this docs commit). Audited 18 Oct 2026 on the developer laptop (Windows 11, Docker Desktop 29.8.2, Python 3.12.10 venv, Node 25.2.1). Nothing has been pushed or deployed.

## Gate report

| Area | Result | Evidence | Remaining issue |
|---|---|---|---|
| Repository integrity | PASS | Release worktree clean; both source branches intact; tags untouched; no force operations | `main` is 67 commits behind the release branch; PRs needed |
| Backend tests | PASS | `python -m pytest -q`: **564 passed**, 0 failed, 0 skipped, 121 s; `ruff check .` clean | — |
| Frontend tests/lint/build | PASS | `npm test`: **30/30**; `npm run lint`: 0 warnings; `npm run build`: OK (one chunk > 500 kB, lazy-loaded shield); `npm audit --omit=dev`: 0 | 3 UI items sent to the UI thread (below) |
| History integration | PASS | Built image served the UI; browser: History list (5 scans, filters, paging), dataset detail, "What was checked", scan history, event timeline, all from real API calls; no layout overflow at 390 px on 6 routes | — |
| Detector accuracy | PASS | Real ClamAV 1.5.4: clean CSV `clean_verified`; whole-file EICAR `Eicar-Test-Signature`; EICAR in a CSV row `malicious` via YARA/MAL-001; formula fixture `suspicious`→remediated; malformed JSON `scan_incomplete`; 51 MB → 413; regression tests for MZ, XLSX, URLhaus pass | — |
| Threat-intel behavior | PASS (mocked) | 21 adapter tests + 11 state tests; live CIRCL check OK; all new providers off by default | Live MalwareBazaar/ThreatFox not run (no key, abuse.ch DNS blocked on this network) |
| Oracle gateway | NOT DEPLOYED | Local stack tested 17 Oct (401/EICAR/413/404/redaction) | Owner must create VM, DNS, token |
| Database durability | DECISION PENDING | `persistence.durable` true on Docker volume, false on Render `/tmp` (tested) | PostgreSQL driver needs approval |
| Security preflight | PASS | `gitleaks git` (59 commits since `origin/main`): no leaks; `gitleaks dir`: no leaks; static no-execution test; hardened container (ro, cap_drop ALL, no-new-privileges) | — |
| Rollback | PASS (documented) | `docs/release/DEPLOYMENT_RUNBOOK.md` | Not rehearsed on Render |

## Branches (verified with Git)

| Branch | Head | Notes |
|---|---|---|
| `release/2026-10-core-bastion` | `2045b7f` | New; `integrate/core-audit` + `feat/bastion-frontend` |
| `integrate/core-audit` | `4e9e514` | Backend track; 15 commits beyond the merge base, incl. `b1fa720` (UTC timestamps) and `4e9e514` (Render blueprint) made during this release check |
| `feat/bastion-frontend` | `3f9b68b` | UI track (owned by the UI thread, checked out in the main worktree); merged into the release branch, not modified |
| `feat/detection-layers` | `9f473b0` | = tag `core-baseline-v2`; empty, unchanged |
| `main` | `9835f02` = `origin/main` | Ancestor of every branch above |

Merge base of the two tracks: `9f473b0`. Only `backend/main.py` and `docs/DEPENDENCIES.md` changed on both sides; both merged automatically (`main.py` keeps gzip, cache headers and the font CSP from the UI track, and `/health/detectors` plus the scans router from the backend track).

## Deployment target (from the repository)

There is **no Vercel configuration** in any branch. The canonical deployment is one Render Docker service: the root `Dockerfile` builds the React app and FastAPI serves it from `backend/static` (same origin, `VITE_API_URL=""`). `render.yaml` allows only `https://aegis-node.onrender.com`. Adding Vercel would create a second frontend build and need CORS and Turnstile changes, so it is a decision for the owner, not part of this release.

## Changes made during this release check

| Commit | Branch | What |
|---|---|---|
| `b1fa720` | integrate/core-audit | Every API timestamp carries `+00:00` (SQLite returned naive UTC; the UI showed it as local time). Test: `tests/test_timestamps_utc.py` |
| `4e9e514` | integrate/core-audit | `render.yaml`: `AEGIS_PROFILE=lite`, `MAX_UPLOAD_SIZE_MB=25`; AV stays MetaDefender |
| `b2ae2c3`, `2045b7f` | release | The two merges |

## Open items

1. **UI:** the 413 message and the provider list are fixed in `44e0017`, merged as `acc0dc2` (frontend 33/33, backend 564 after the merge). Still open: `/analysis` 404 logs a console error when no analysis exists (harmless; needs a backend change).
2. **PostgreSQL:** needs approval (see below).
3. **Oracle:** owner-side setup.
4. **Signatures in the test image** were dated 27 Sep 2026 on first start (bundled database before freshclam's first update); on the VM, check `/api/v1/version` after the first freshclam run.
5. **abuse.ch** does not resolve with this laptop's DNS (Cloudflare 1.1.1.1 resolves it). No workaround was applied.

## PostgreSQL decision

SQLite on Render lives in `/tmp` and is lost on every restart or redeploy; `persistence.durable` already reports `false` there. A Neon URL alone does not work: no PostgreSQL driver is installed.

| Option | Package | Licence | Notes (PyPI, 18 Oct 2026) |
|---|---|---|---|
| A (recommended) | `psycopg[binary]==3.3.6` | **LGPL-3.0-only**; the binary wheel bundles libpq (PostgreSQL licence) and OpenSSL | Released 18 Sep 2026; wheels for cp312 linux x86_64 (5 MB), aarch64, Windows; SQLAlchemy URL `postgresql+psycopg://`. LGPL is used as an unmodified library, which permits use from MIT/proprietary code |
| B | `pg8000==1.31.5` | BSD-3-Clause (deps: `scramp`, `python-dateutil`) | Pure Python, no binary; last release 14 Sep 2025, which is over the project's 12-month rule |
| C | stay on SQLite | — | Preview with an explicit "history is temporary" warning (already shown by the UI) |

Either A or B needs: the dependency pin, `DATABASE_URL` with `sslmode=require` for Neon, a startup test with valid / missing / malformed URLs, the existing Alembic-free migrations run against PostgreSQL, and a persistence test across restarts.
