# GitHub push audit

18 Oct 2026, under the owner's push authorization (11:54 UTC). Deployment (Render, Vercel, Oracle) and merging into `main` are not authorized and were not done.

## State before the push (verified with Git after `git fetch origin --prune`)

| Branch | Local head | On origin before | Action |
|---|---|---|---|
| `integrate/core-audit` | `4e9e514` | absent | push, PR into `main` (review) |
| `feat/bastion-frontend` | `44e0017` | absent | push, PR into `main` (review) |
| `release/2026-10-core-bastion` | `acc0dc2` + this docs commit | absent | push, PR into `main` (the one to merge) |
| `main` | `9835f02` | `9835f02` | untouched |
| `feat/detection-layers` | `9f473b0` | absent | not pushed: ancestor of every branch above, no own commits |
| `fix/audit-2026-10` | `722c477` | absent | not pushed: already contained in the release branch |
| `ai-security-validation`, `oss-security-research`, `security-hardening-audit`, `validation-v1` | — | — | not pushed: nothing beyond `main` |

Tags `core-baseline-v2` (`9f473b0`) and `core-freeze-2026-10-13` (`c895a6b`) stay local; no tags are pushed.

`acc0dc2` merges `44e0017` (UI release-check fixes: providers from `/health/detectors`, server upload limit, CIRCL "Known file (annotation)") into the release branch, on top of `e9d0c71` (readiness docs), `2045b7f` and `b2ae2c3` (the two track merges).

## Uncommitted files, not pushed

- Main checkout (`Aegis-Node`, `feat/bastion-frontend`): untracked `scripts/get_logs.ps1`. Not part of any completed work; left in place, not committed.
- Release and backend worktrees: clean.

## Checks on the pushed release head

| Check | Result |
|---|---|
| Backend `pytest -q` | 564 passed |
| `ruff check .` | clean |
| Frontend `npm test` / lint / build | 33/33, 0 warnings, built |
| `gitleaks git` on `origin/main..` each pushed branch | no leaks (63 commits on the release branch) |
| Paths added since `origin/main` | no `.env`, databases, logs, keys, binaries, `node_modules` or virtual environments |

No force push, no history rewrite, no branch or tag deleted.
