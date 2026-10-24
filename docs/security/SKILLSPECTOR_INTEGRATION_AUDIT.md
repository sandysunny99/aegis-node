# SkillSpector integration audit

Date: 2026-10-24. Branch: `claude/project-thread-6xpnu9`, cut from `main` at `1de487b`.
Scope: evaluate NVIDIA SkillSpector as a security scanner for the agent skills, rules and
scripts used to build Aegis Node, and integrate it only where justified.

Labels used below: **Verified** means run or read in this audit. **Recommendation** is a
proposal for the owner. **Unverified** means stated by a source but not checked here.

## 1. Result in one paragraph

SkillSpector is useful to Aegis as an isolated, static, report-only development tool. It
was installed outside the repository at a pinned commit, run with LLM analysis off and
outbound HTTP blocked, and pointed at 8 approved targets (21 files). It found 0 critical,
3 high and 10 medium findings. After manual review, 8 are false positives and 5 are
accepted risks (owner sign-off still needed); none was a confirmed risk, so no Aegis code
was changed because of a finding. A test-first wrapper (`scripts/skill_scan.py`, 35 tests)
and a report-only GitHub Actions job were added. The production dataset scanner, backend
dependencies, frontend dependencies, deploy config and any user-wide Claude or MCP
configuration are unchanged.

## 2. Aegis baseline (Phase 1) - verified

| Item | State found |
|---|---|
| Git | Fresh cloud clone of `sandysunny99/aegis-node`; one worktree; `main` = `origin/main` = `1de487b` |
| Agent instruction files in git | `AGENTS.md` only (headed "Antigravity Agent Rules") |
| `CLAUDE.md`, `.claude/`, `.agents/`, `skills/`, `SKILL.md`, MCP config (`.mcp.json`, `mcpServers`) | None tracked in git |
| Agent guidance docs | `docs/AGENT_WORKFLOW.md`, `docs/AGENT_TOOLCHAIN.md`, `docs/AGENT_TOOLCHAIN_AUDIT.md`, `docs/SCIENTIFIC_SKILLS_CONFIGURATION.md`, `docs/CYBERSECURITY_SKILLS_SELECTION.md`. They name external skill packs (K-Dense scientific skills, mukul975 cybersecurity skills) as "Antigravity only"; the skill files themselves are not in the repo |
| CI | `.github/workflows/ci.yml`: ruff + pytest, frontend lint/build, gitleaks; `permissions: contents: read`; no agent steps |
| Scripts | `scripts/`: 9 PowerShell and 3 Python helpers (local serve, smoke tests, ClamAV checks, Docker cleanup) |
| LLM prompts and guardrails | `backend/services/llm_service.py`, `guardrails.py`, `ai_providers/*`: production dataset-analysis code, not agent tooling |
| Secret scanning | gitleaks in CI; `.env`/`*.env` git-ignored |

**Limitation:** the owner's laptop checkout may hold untracked agent files (`.claude/`,
skills, MCP settings) that never reach git. This audit could not see them. They can be
scanned locally with the same script by adding them to the policy file (section 9).

## 3. SkillSpector review (Phase 2)

### Revision evaluated - verified

| Field | Value |
|---|---|
| Repository | https://github.com/NVIDIA/SkillSpector |
| Commit | `d7338f58200a9ae2a24810cee08911ab68b107a7` (2026-10-22, merge of PR #841) |
| Package version | 2.12.0 (`pyproject.toml`), classifier "Development Status :: 3 - Alpha" |
| Licence | Apache-2.0 (`LICENSE`, `pyproject.toml`) |
| Python | `>=3.12,<3.15`; installed with 3.12 to match Aegis CI |
| Files read | `README.md`, `docs/DEVELOPMENT.md`, `docs/ANALYSIS_RESOURCE_BOUNDS.md`, `docs/SUPPRESSION.md`, `docs/scan-completeness.md`, `docs/SC4-osv-live-vulnerability-lookups.md`, `pyproject.toml`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `skillspector scan --help` |

### Capabilities

| Capability | Status for this checkout |
|---|---|
| Static analysis of skills and instruction files | Verified: regex, Python AST, taint tracking and YARA ran on Markdown, Python, YAML and PowerShell files |
| Prompt injection, exfiltration, credential access, supply chain, excessive agency, tool misuse | Verified on synthetic fixtures: P1/P2/AR3/YR4 (injection), PE3/E2/TT4/E1 (credential exfiltration), SC2 (`curl | bash`) |
| Pattern count | **Not as advertised.** The README headline says 71 patterns in 17 categories; its own tables list 73 rule ids in 17 sections, and the source references more (AE1-AE7, AS1-AS3, AST10, E5, PE4-PE5, SC7, TM4, TT6). Do not quote "71" for this commit |
| Optional LLM semantic analysis | Present; **not used**. Default provider is NVIDIA's (`nv_build`/`nv_inference`); it sends file contents to the provider |
| Risk score, severity, recommendation | Verified (section 4) |
| JSON, Markdown, SARIF output | JSON verified and used; SARIF and Markdown not used |
| MCP server (`skillspector mcp`, tool `scan_skill`) | Read only; needs the `[mcp]` extra, which was not installed (section 7) |
| Resource bounds and incomplete-analysis reporting | Verified: a missing reference produced `partial`, a UTF-16 `SKILL.md` produced `failed` |
| Baselines (fingerprint and glob suppression) | Read; not used (section 6) |

### Limitations - verified unless marked

- **Exit code 0 is not a safety verdict.** A partial scan (missing referenced file plus an
  opaque image) exited 0 with `CAUTION`, score 25. A failed scan (UTF-16 `SKILL.md`) exited
  2 with `CAUTION`, score 9, severity LOW. Only `analysis_completeness.is_complete`,
  `.status` and `execution_successful` separate these from a clean scan.
- **Network even with `--no-llm`.** SC4 sends declared dependency names and versions to
  `api.osv.dev`, documented as running with `--no-llm`. The wrapper points HTTP(S) at an
  unroutable local proxy, so SC4 falls back to the built-in list. None of the current
  targets declares dependencies.
- **PowerShell gets generic checks only.** `.ps1` files are typed `other`: regex checks run,
  AST and taint analysis do not. Manual review found `scripts/cleanup.ps1` runs
  `docker compose down -v` and `Stop-Process -Force` with no confirmation; SkillSpector did
  not flag it (section 5).
- **Hex-encoded payloads in strings are not decoded.** `scripts/internal_eicar_test.ps1`
  embeds the EICAR test string as hex inside a Python here-string; no SC3 finding.
- **Unicode check false positive.** A UTF-8 BOM on a two-line file triggers AE4. Verified by
  scanning the same file with and without the BOM.
- **Negation is not understood** by static rules: "NEVER automatically execute" matched EA2.
- **Working tree, not git.** The scanner reads whatever is on disk. A `__pycache__/` left by
  a test run produced SC8/SC9 HIGH findings; the tests now disable bytecode writing.
- **Results change between versions.** The project merges changes daily; fingerprints are
  tied to the scanner version. Hence the pin.
- **Prompt injection against the scanner.** Static mode never gives skill text to a model, so
  there is nothing to manipulate. The README says LLM prompts carry anti-jailbreak
  protections (unverified).
- **Remote ingestion** (Git URL, zip URL) exists with a 100 MiB ingest cap and redirect
  rejection (unverified). The wrapper accepts only local paths inside the repo.
- **Third-party notices are incomplete.** `THIRD_PARTY_NOTICES.md` lists 12 runtime
  packages; the locked install pulled 69 distributions.

## 4. Output semantics - verified

| Situation | Exit | `recommendation` | `analysis_completeness.status` | Wrapper status |
|---|---|---|---|---|
| Benign skill | 0 | SAFE | complete | complete |
| Findings, score <= 50 | 0 | SAFE or CAUTION | complete | complete (findings go to triage) |
| Findings, score > 50 | 1 | DO_NOT_INSTALL | complete | complete (findings go to triage) |
| Missing reference, opaque file | 0 | CAUTION | partial | **incomplete** (fails the gate) |
| Unreadable primary content | 2 | CAUTION | failed | **tool_error** (fails the gate) |
| Timeout, crash, no output, wrong version | n/a | n/a | n/a | **tool_error** (fails the gate) |
| Malformed, oversized or LLM-mode report | any | any | any | **invalid_report** (fails the gate) |

SkillSpector maps severity to recommendation (`LOW` SAFE, `MEDIUM` CAUTION, `HIGH`/`CRITICAL`
DO_NOT_INSTALL) and raises an incomplete `SAFE` to `CAUTION`. A failed or partial scan never
becomes a pass in the wrapper, whatever the score.

## 5. Inventory and baseline scan (Phases 3 and 6)

### What was scanned

| Target | Path | Type | Exists | Origin | Secrets | Supported | Remote or LLM needed |
|---|---|---|---|---|---|---|---|
| agents-md | `AGENTS.md` | Antigravity rules | yes | local | no | yes | no |
| agent-workflow | `docs/AGENT_WORKFLOW.md` | agent guidance | yes | local | no | yes | no |
| agent-toolchain | `docs/AGENT_TOOLCHAIN.md` | agent guidance | yes | local | no | yes | no |
| agent-toolchain-audit | `docs/AGENT_TOOLCHAIN_AUDIT.md` | agent guidance | yes | local | no | yes | no |
| scientific-skills | `docs/SCIENTIFIC_SKILLS_CONFIGURATION.md` | agent guidance | yes | local (names an external MIT skill pack) | no | yes | no |
| cybersecurity-skills | `docs/CYBERSECURITY_SKILLS_SELECTION.md` | agent guidance | yes | local (names an external skill pack) | no | yes | no |
| scripts | `scripts/` (13 files) | scripts agents run | yes | local | `verify_gateway.py` loads `.env` at run time; no secret in the file | `.py` fully, `.ps1` regex only | no |
| ci-workflows | `.github/workflows/` (2 files) | release automation | yes | local | references `secrets.GITHUB_TOKEN` only | yes | no |

Not scanned, with reasons, is recorded in `security/skill_scan_targets.json` (`exclusions`):
synthetic test fixtures, production LLM prompt code, datasets, general docs, and the
laptop-only agent files that are not in git. Not present at all: `CLAUDE.md`, `SKILL.md`
files, MCP configuration.

### Run facts - verified

- Mode: `--no-llm`, JSON; via `scripts/skill_scan.py` (minimal env, no keys, dead proxy).
- Runtime: about 5 s per single-file target, 8 s for `scripts/`, 44 s in total.
- Raw report size: 12 to 30 KB per target (not committed; contains snippets and paths).
- Coverage: all 8 targets `complete`, 100 %.
- Sanitized reports: `reports/security/skillspector-baseline.{json,md}` (before triage) and
  `reports/security/skillspector-after-triage.{json,md}`. They hold rule ids, files, lines and
  keys only.

### Findings and triage

| Key | Target | Rule | Sev. | Location | Classification | Evidence |
|---|---|---|---|---|---|---|
| `779b0d6aca5eec7d` | scripts | PE3 | HIGH | `serve_local.ps1:4` | false positive | Line 4 is a comment that mentions `.env`; the file is never read |
| `475efe2b2932f6b8` | scripts | PE3 | HIGH | `verify_gateway.py:13` | accepted risk | Loads `.env` to call Groq with a fixed prompt; real keys and paid calls, so agents run it only on request |
| `c2721df122b4d47c` | ci-workflows | TM2 | HIGH | `ci.yml:25` | accepted risk | `sudo apt-get install libmagic1` on an ephemeral hosted runner, `contents: read` |
| `247711d5f05ce1aa` | ci-workflows | PE2 | MEDIUM | `ci.yml:25` (x2) | accepted risk | Same line |
| `1361abeab0e6ccb4` | agents-md | EA2 | MEDIUM | `AGENTS.md:7` | false positive | Matched inside "NEVER automatically execute" |
| `1f0f0b857781e17d` | scripts | AE4 | MEDIUM | `debug_logs.ps1:1` | false positive | UTF-8 BOM; no finding without it (tested) |
| `9864d1c804a8fa35` | scripts | AE4 | MEDIUM | `debug_scan.ps1:1` | false positive | Same BOM pattern |
| `5a05309530dca327`, `696ab3c72c8028c3` | scripts | AST4 | MEDIUM | `skill_scan.py` | accepted risk | The wrapper must start the scanner; argument list, no shell, timeout |
| `2009c7eadbd26131`, `40e009c84fa5feaa` | scripts | TT2 | MEDIUM | `skill_scan.py` | accepted risk | Inputs are the policy-validated path and constant flags |
| `85ac3115f9af6cd7`, `88956b1adb464154` | scripts | TT2 | MEDIUM | `smoke_fresh_db.py:18,23` | false positive | Dataset id from 127.0.0.1 sent back to 127.0.0.1 |

Totals: 13 findings (0 critical, 3 high, 10 medium, 0 low); 0 confirmed, 0 likely,
8 false positives, 5 accepted risks, 0 incomplete. The owner field of every entry says
"proposed by Claude, awaiting owner review" until Sandeep confirms it.

### Manual-review items the scanner missed (need owner review)

1. `scripts/cleanup.ps1` force-kills whatever listens on ports 8000 and 5173 and runs
   `docker compose down -v`, which deletes the compose volumes (local SQLite history,
   quarantine). Likely risk if an agent runs it unprompted. Suggested mitigation: a
   confirmation prompt or a `-RemoveVolumes` switch. Not changed here, because it alters
   script behaviour the owner relies on.
2. `scripts/verify_gateway.py` makes real, billable Groq calls with the local keys. Covered
   by the accepted-risk entry above; agents should only run it when asked.
3. `scripts/internal_eicar_test.ps1` writes the EICAR test string (hex-encoded) and uploads it
   to the local server. Intended test behaviour; noted because SkillSpector does not decode it.

## 6. Integration decision (Phase 4)

| Option | Decision | Why |
|---|---|---|
| A. Isolated dev tool | **Adopted** | No production change, no new Aegis dependency, easy to remove |
| B. CI gate | **Adopted as report-only** (`.github/workflows/skill-scan.yml`) | Runs on PRs that touch agent files or scripts, and on demand; never blocks. Promote to blocking after the owner signs off the triage (section 9) |
| C. MCP server for Claude Code | **Not adopted now** | Aegis has no skills or MCP servers in git to gate; the stdio transport still has the initialize hang (issue #199, per README); HTTP has no auth. No global or project MCP config was written |

Not done on purpose: no SkillSpector source or rules copied into Aegis; no change to the
dataset scanner, verdicts or risk score; no SkillSpector baseline file. The wrapper keeps its
own triage file because SkillSpector baselines carry a reason but no classification or owner,
and because suppressing in the scanner lowers its raw score, which the sanitized report keeps.

## 7. Installation, dependencies and licences (Phase 5) - verified

- Installed from a clone at the pinned commit into a separate venv outside the repo:
  `UV_PROJECT_ENVIRONMENT=<venv> uv sync --frozen --no-dev --python 3.12` (uses the project's
  `uv.lock`). No `[mcp]`, `[dev]` or `[langgraph-dev]` extras.
- 69 Python distributions, 217 MB on disk. Includes LangGraph, LangChain, openai, anthropic,
  boto3, google-auth and yara-python, even for static use.
- Licences from installed metadata: MIT, BSD, Apache-2.0, ISC, PSF, plus MPL-2.0 (certifi;
  parts of orjson and tqdm) and CNRI-Python (part of regex). **No GPL or AGPL.** MPL-2.0 is
  file-level copyleft and applies only if those files are modified; they are used unmodified
  in a separate venv.
- Aegis `requirements*.txt`, `package.json` and lockfiles: unchanged. Aegis backend Python:
  unchanged (CI already uses 3.12).
- Network during install: GitHub (clone) and PyPI (locked wheels). During scans: none
  (dead proxy), verified by design of the env and covered by a test that checks the
  scanner's environment.
- **Needs owner approval:** the tool is 217 MB with its dependencies, above the project's
  50 MB review threshold, and is alpha. It stays out of the Aegis runtime either way; the
  question is only whether the CI job may install it.

## 8. Resource bounds (Phase 9)

SkillSpector defaults (documented, not all exercised): 10,000 entries per bundle, 16 MiB per
cached artifact, 64 MiB per bundle, 600 s workflow, 30 s discovery, 1 MB analyzer read per
file, nested ZIP depth 3 / 1,000 members / 25 MiB. Wrapper limits on top
(`security/skill_scan_targets.json`): 180 s per target, 50 files per target, 1 MiB per file,
5 MiB per report, 2,000 issues per report, one target at a time, temporary directory removed
after each target, no URLs, no LLM.

## 9. Tests (Phase 7) - verified

`tests/test_skill_scan.py`: 35 tests (34 with a fake scanner, 1 against the real pinned
SkillSpector when `SKILLSPECTOR_BIN` is set). Written first and run against a naive wrapper
that trusted the exit code and recommendation: **32 failed, 2 passed, 1 skipped**. After the
wrapper was implemented: **35 passed** (with the real scanner), 34 passed and 1 skipped without
it. Coverage of the 10 required cases: benign, prompt injection, credential exposure,
malformed report (6 shapes) and oversized report, process failure, exit 2 with report,
timeout, incomplete analysis with a SAFE recommendation, triage with reason and owner,
triage without reason, confirmed risk, mismatched triage, unapproved paths (7 shapes),
symlink, file-count cap, shipped baseline, argument-list and secret-free environment,
reviewer-manipulation text (gate fails, text not printed or written), no snippets or
absolute paths in outputs, pinned-version mismatch, LLM-mode report.

Full Aegis suite and checks for this change: see section 11.

## 10. Separation from dataset verdicts (Phase 8)

SkillSpector output lives only in `reports/security/` summaries and CI artifacts. Nothing in
`backend/` or `scanner/` imports or reads it. It never changes a dataset status, risk score or
verdict, and Aegis never sends uploaded datasets to SkillSpector. Any future comparison with
Aegis's prompt-injection detectors needs its own approved evaluation on synthetic fixtures.

## 11. Changes and release impact (Phases 12 to 14)

| Area | Changed? |
|---|---|
| Production dataset scanner, backend code | No |
| Backend dependencies (`requirements*.txt`) | No |
| Frontend dependencies | No |
| `render.yaml`, Dockerfile, deploy config | No |
| CI | New report-only workflow `skill-scan.yml`; `ci.yml` unchanged. Inert until the branch is pushed and merged |
| User-wide Claude or MCP configuration | No (none read or written) |

Files added: `scripts/skill_scan.py`, `security/skill_scan_targets.json`,
`security/skill_scan_triage.json`, `tests/test_skill_scan.py`,
`tests/fixtures/skill_security/` (4 synthetic skills), `.github/workflows/skill-scan.yml`,
`reports/security/skillspector-{baseline,after-triage}.{json,md}`, this file,
`docs/security/AGENT_SKILL_THREAT_MODEL.md`, `docs/security/SKILL_SECURITY_SCANNING.md`.
Files updated: `docs/DEPENDENCIES.md`, `docs/DEPLOYMENT_RELEASE_CHECKLIST.md`,
`docs/DECISIONS.md`, `.gitignore`.

Verification for the commit (cloud container, Python 3.12): full pytest **604 passed, 2
skipped** (the 2 skips predate this change; 571 tests before plus 35 new, with
`SKILLSPECTOR_BIN` set); `ruff check .` clean; gitleaks 8.24.2 `dir` and `git` (86 commits):
no leaks; workflow YAML parses. Frontend lint and build not run: no frontend file changed.
The CI workflow itself was not executed (no runner here); its install commands match the
ones run locally.

## 12. Remaining work and owner decisions

1. Confirm or change the 13 triage entries (owner field says "awaiting owner review").
2. Decide on `scripts/cleanup.ps1` (`docker compose down -v` without a prompt).
3. Approve or reject installing the 217 MB alpha tool in CI (section 7).
4. Scan the laptop-only agent files (`.claude/`, skills, MCP settings) locally, or commit the
   ones that should be shared.
5. After 1 and 3, decide when to switch the workflow from `--mode report` to `--mode gate`.
6. Re-pin deliberately: when moving to a newer SkillSpector, rerun, compare with
   `reports/security/skillspector-after-triage.json`, and re-triage changed keys.
7. Not pushed. Nothing deployed.
