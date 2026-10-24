# SkillSpector integration audit

Date: 2026-10-24. First run on `claude/project-thread-6xpnu9` (from `main` at `1de487b`);
revised on `feat/skillspector-security-audit` (from `main` at `253c7ae`) after the owner's review.
Scope: evaluate NVIDIA SkillSpector as a security scanner for the agent skills, rules and
scripts used to build Aegis Node, and integrate it only where justified.

Labels used below: **Verified** means run or read in this audit. **Recommendation** is a
proposal for the owner. **Unverified** means stated by a source but not checked here.

## 1. Result in one paragraph

SkillSpector is useful to Aegis as an isolated, static, **local-only**, report-only
development tool. It was installed outside the repository at a pinned commit, run with LLM
analysis off and outbound HTTP blocked, and pointed at 8 approved targets. The first run
found 13 findings (0 critical, 3 high, 10 medium). On review, none was a confirmed risk;
two scripts behind accepted risks were still hardened at the owner's request
(`cleanup.ps1`, `verify_gateway.py`). The current run finds 14 findings covering 17 matches
(4 high, 10 medium): 7 false positives and 7 accepted risks, all approved by the
owner on 2026-10-24 with conditions (section 5). A test-first wrapper (`scripts/skill_scan.py`) was added. The hosted CI job is
deferred because the tool's environment is 217 MB and alpha. The production dataset
scanner, backend and frontend dependencies, deploy config and any user-wide Claude or MCP
configuration are unchanged.

**Correction (2026-10-24).** The first version of this report said "8 false positives and
5 accepted risks". That was wrong: the triage file it shipped with had 6 false positives
and 7 accepted risks. The owner caught it. The totals below are now checked against the
triage file and reports by `tests/test_skill_scan_records.py`.

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

Two runs are recorded. A finding is one triage key: target, rule, file and matched text. When
the same text matches on several lines, SkillSpector reports each match, and the wrapper groups
them under one key with an occurrence count. A triage entry records how many matches it
reviewed; if that number changes, the entry stops applying until it is reviewed again.

Baseline totals (first run, `reports/security/skillspector-baseline.*`, before any script
change): 13 findings (14 matches): 0 critical, 3 high, 10 medium, 0 low; 6 false positives, 7 accepted risks, 0 confirmed, 0 likely, 0 incomplete.
SkillSpector reported PE2 twice on `ci.yml:25` (once per `sudo`). That baseline file is
older than the occurrence count, so it shows 13 grouped rows.

Current totals (`reports/security/skillspector-after-triage.*`, this branch): 14 findings (17 matches): 0 critical, 4 high, 10 medium, 0 low; 7 false positives, 7 accepted risks, 0 confirmed, 0 likely, 0 incomplete.
The new finding is `dbe350a3ee7e62e3`: the opt-in text added to `verify_gateway.py` mentions
`.env` three times.

| Group | Keys (rule, location, matches) | Classification | Evidence and safeguard |
|---|---|---|---|
| `.env` named in text, not read | `779b0d6aca5eec7d` (PE3 HIGH, `serve_local.ps1:4`, 1); `dbe350a3ee7e62e3` (PE3 HIGH, `verify_gateway.py:3,28,87`, 3) | false positive | Comment, docstrings and a printed message; nothing reads the file there |
| Paid Groq check reads `.env` | `475efe2b2932f6b8` (PE3 HIGH, `verify_gateway.py:32`, 1) | accepted risk | New safeguard: does nothing and loads nothing without `--confirm-paid-calls`; keys never printed; never run by tests, CI or the scan |
| CI installs a package as root | `c2721df122b4d47c` (TM2 HIGH, `ci.yml:25`, 1); `247711d5f05ce1aa` (PE2 MEDIUM, `ci.yml:25`, 2) | accepted risk | Ephemeral GitHub-hosted runner, `permissions: contents: read`, the job references no secrets (only the separate gitleaks job uses `GITHUB_TOKEN`), no deploy step |
| Wrapper starts the scanner | `5a05309530dca327`, `696ab3c72c8028c3` (AST4 MEDIUM, `skill_scan.py`, 1 each) | accepted risk | Argument list, `shell=False`, stdin closed, timeout, `--no-llm`, report size cap; tests check argv |
| Environment flows into the scanner call | `2009c7eadbd26131`, `40e009c84fa5feaa` (TT2 MEDIUM, `skill_scan.py`, 1 each) | accepted risk | SkillSpector traces `env` from `os.environ.get`. Only `PATH` (plus `SYSTEMROOT`, `WINDIR`, `COMSPEC`, `PATHEXT` on Windows) is copied from the host; the rest is constant and proxies point at 127.0.0.1:9. The target path comes from the policy and passes `_resolve_target`. A test asserts no `KEY`/`TOKEN`/`SECRET` variable reaches the scanner |
| Negated rule text | `1361abeab0e6ccb4` (EA2 MEDIUM, `AGENTS.md:7`, 1) | false positive | Matched inside "NEVER automatically execute" |
| UTF-8 BOM | `1f0f0b857781e17d` (AE4 MEDIUM, `debug_logs.ps1:1`), `9864d1c804a8fa35` (AE4 MEDIUM, `debug_scan.ps1:1`) | false positive | Two-line ASCII scripts; same file without the BOM gives no AE4 (tested) |
| Local round trip | `85ac3115f9af6cd7`, `88956b1adb464154` (TT2 MEDIUM, `smoke_fresh_db.py:18,23`) | false positive | Dataset id from 127.0.0.1 sent back to 127.0.0.1 |

**Owner sign-off (Sandeep, 2026-10-24).** All 14 dispositions are approved as listed:
7 `false_positive`, 7 `accepted_risk`; each entry's owner field reads
"Sandeep (owner-approved 2026-10-24)". Keys, rules, evidence and reasons are unchanged, and
on `main` at `d5d34c6` the scan reproduces exactly these 14 findings with no stale or changed
entries. The approval covers these individual, documented findings only. It is not blanket
approval for agents to run scripts or read secrets, and it rests on these conditions:

- `verify_gateway.py` (`475efe2b2932f6b8`, HIGH): accepted only because paid calls need
  `--confirm-paid-calls`; run it only when the owner explicitly asks.
- `skill_scan.py` (`5a05309530dca327`, `696ab3c72c8028c3`, `2009c7eadbd26131`,
  `40e009c84fa5feaa`): keep the argument-list call, `shell=False`, closed stdin, timeout,
  `--no-llm`, the minimal environment and its no-key/token/secret test, the dead proxy,
  bounded reports, and the in-repo, no-symlink target checks.
- `ci.yml` (`c2721df122b4d47c`, `247711d5f05ce1aa`): covers the existing `libmagic1` install on
  an ephemeral hosted runner only, with least-privilege permissions and no secrets in that job;
  not arbitrary privileged commands or unreviewed workflow changes.
- `cleanup.ps1`: no accepted-risk entry is needed for the old behaviour, provided the default
  keeps volumes and deletion still needs `-RemoveVolumes` plus the exact phrase, as
  `tests/test_cleanup_script.py` checks.
- The SkillSpector CI workflow stays removed; this approval does not cover restoring it or
  adding SkillSpector to the normal CI job.

A static scan, even fully triaged, is not proof that these scripts or skills are safe at
run time.

### Manual-review items the scanner missed

1. `scripts/cleanup.ps1` used to force-kill whatever listened on ports 8000 and 5173 and run
   `docker compose down -v`, deleting the Aegis volumes. **Fixed at the owner's request:** the
   default now only runs `docker compose down`; `-StopListeners` offers to stop
   python/uvicorn/node dev servers one at a time (no `-Force`, never without a console);
   `-RemoveVolumes` lists the declared Aegis volumes that exist and deletes exactly those
   after the typed phrase `DELETE AEGIS DATA` (refused without a console unless
   `-ConfirmDeletion` carries it); `-DryRun` changes nothing. `tests/test_cleanup_script.py`
   runs the real script under PowerShell with stubbed docker and process commands: all 11
   behaviour and static checks failed on the old script and pass now. The interactive
   prompts themselves are not exercised by the tests.
2. `scripts/verify_gateway.py` makes real, billable Groq calls with the local keys. Now
   gated by `--confirm-paid-calls` (accepted-risk entry above).
3. `scripts/internal_eicar_test.ps1` writes the EICAR test string (hex-encoded) and uploads it
   to the local server. Intended test behaviour; noted because SkillSpector does not decode it.

## 6. Integration decision (Phase 4)

| Option | Decision | Why |
|---|---|---|
| A. Isolated dev tool | **Adopted** | No production change, no new Aegis dependency, easy to remove |
| B. CI gate | **Deferred** | The owner declined installing the 217 MB alpha environment in hosted CI for now (50 MB threshold). The reviewed workflow is kept inactive at `docs/security/deferred/skill-scan.workflow.yml.txt` |
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
- **Owner decision (2026-10-24): not in hosted CI for now.** The tool is 217 MB with its
  dependencies, above the project's 50 MB review threshold, and alpha. It runs only in a
  local isolated venv. Later options for review: a pre-provisioned self-hosted runner with
  the venv cached, a documented exception, or a lighter scanner.

## 8. Resource bounds (Phase 9)

SkillSpector defaults (documented, not all exercised): 10,000 entries per bundle, 16 MiB per
cached artifact, 64 MiB per bundle, 600 s workflow, 30 s discovery, 1 MB analyzer read per
file, nested ZIP depth 3 / 1,000 members / 25 MiB. Wrapper limits on top
(`security/skill_scan_targets.json`): 180 s per target, 50 files per target, 1 MiB per file,
5 MiB per report, 2,000 issues per report, one target at a time, temporary directory removed
after each target, no URLs, no LLM.

## 9. Tests (Phase 7) - verified

`tests/test_skill_scan.py`: 37 tests (36 with a fake scanner, 1 against the real pinned
SkillSpector when `SKILLSPECTOR_BIN` is set). The first 34 were written before the wrapper
and run against a naive version that trusted the exit code and recommendation: **32 failed,
2 passed, 1 skipped**. Two were added with the occurrence-count rule. Coverage of the 10
required cases: benign, prompt injection, credential exposure, malformed report (6 shapes)
and oversized report, process failure, exit 2 with report, timeout, incomplete analysis
with a SAFE recommendation, triage with reason and owner, triage without reason or
occurrence count, confirmed risk, mismatched triage, a new match under a reviewed key,
unapproved paths (7 shapes), symlink, file-count cap, shipped baseline, argument list and
secret-free environment, reviewer-manipulation text (gate fails, text not printed or
written), no snippets or absolute paths in outputs, pinned-version mismatch, LLM-mode report.

`tests/test_skill_scan_records.py` checks the committed records against each other: triage
file, both sanitized reports, and the totals lines in section 5 of this file.

`tests/test_cleanup_script.py`: 13 tests (3 static, 8 under PowerShell with stubs, 2 for
`verify_gateway.py`). The PowerShell ones skip when `pwsh` is missing; GitHub's Ubuntu
runners have it.

## 10. Separation from dataset verdicts (Phase 8)

SkillSpector output lives only in `reports/security/` summaries and CI artifacts. Nothing in
`backend/` or `scanner/` imports or reads it. It never changes a dataset status, risk score or
verdict, and Aegis never sends uploaded datasets to SkillSpector. Any future comparison with
Aegis's prompt-injection detectors needs its own approved evaluation on synthetic fixtures.

## 11. Changes and release impact (Phases 12 to 14)

| Area | Changed? |
|---|---|
| Production dataset scanner, `backend/`, `scanner/` | No |
| Backend dependencies (`requirements*.txt`) | No |
| Frontend code and dependencies | No |
| `render.yaml`, Dockerfile, deploy config | No |
| CI | No. `ci.yml` unchanged; the SkillSpector workflow is deferred (not in `.github/workflows/`). The new tests run in the existing pytest job |
| Local scripts | `scripts/cleanup.ps1` (safe default) and `scripts/verify_gateway.py` (opt-in) |
| User-wide Claude or MCP configuration | No (none read or written) |

Commits on `feat/skillspector-security-audit`: the original SkillSpector commit
(cherry-picked from `3ed885e`), the script hardening, and the triage reconciliation with the
CI deferral. Test results for the branch are in the thread report and the last commit message.

## 12. Remaining work and owner decisions

1. Done 2026-10-24: owner approved all 14 triage entries (section 5). Any new or changed
   finding needs a fresh owner review.
2. Decide later whether SkillSpector may run in CI (self-hosted runner, exception, or not).
3. Scan the laptop-only agent files (`.claude/`, skills, MCP settings) locally, or commit the
   ones that should be shared.
4. Re-pin deliberately: when moving to a newer SkillSpector, rerun, compare with
   `reports/security/skillspector-after-triage.json`, and re-triage changed keys.
5. Nothing deployed by this work.
