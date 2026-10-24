# Scanning agent skills with SkillSpector

How to run, read and maintain the static agent-skill scan. Background and results:
`docs/security/SKILLSPECTOR_INTEGRATION_AUDIT.md`. Threats: `AGENT_SKILL_THREAT_MODEL.md`.

This scan is for the agent skills, rules, scripts and CI that build Aegis. It is not part of
the dataset pipeline and its results never change a dataset verdict.

## Pieces

| File | Role |
|---|---|
| `scripts/skill_scan.py` | Wrapper: validates targets, runs SkillSpector statically, validates the report, applies triage, writes sanitized summaries |
| `security/skill_scan_targets.json` | Pinned SkillSpector version and commit, limits, approved targets, recorded exclusions |
| `security/skill_scan_triage.json` | Reviewed findings: key, classification, reason, owner, date |
| `tests/test_skill_scan.py` | Wrapper tests (fake scanner; one optional real-scanner test) |
| `.github/workflows/skill-scan.yml` | Report-only CI job |
| `reports/security/skillspector-*.{json,md}` | Committed sanitized baselines; routine runs write `skillspector-summary.*` there (git-ignored) |

## Install SkillSpector (once, outside the repo)

Linux or macOS (Python 3.12 and `uv` required):

```bash
git clone https://github.com/NVIDIA/SkillSpector.git ~/tools/skillspector-src
git -C ~/tools/skillspector-src checkout d7338f58200a9ae2a24810cee08911ab68b107a7
cd ~/tools/skillspector-src
UV_PROJECT_ENVIRONMENT=~/tools/skillspector-venv uv sync --frozen --no-dev --python 3.12
~/tools/skillspector-venv/bin/skillspector --version   # SkillSpector v2.12.0
```

Windows (PowerShell): same steps with `$env:UV_PROJECT_ENVIRONMENT = "$HOME\tools\skillspector-venv"`;
the executable is `$HOME\tools\skillspector-venv\Scripts\skillspector.exe`. The wrapper reads
the report from stdout, so SkillSpector's POSIX-only `--output` limitation does not apply.
Not tested on Windows in this audit.

Do not install it into the Aegis venv or add it to `requirements*.txt`.

## Run

```bash
python scripts/skill_scan.py --scanner ~/tools/skillspector-venv/bin/skillspector --mode report
python scripts/skill_scan.py --scanner ~/tools/skillspector-venv/bin/skillspector --mode gate
```

- `report` always exits 0 and prints what the gate would decide.
- `gate` exits 1 when any target is not `complete`, when a HIGH/CRITICAL finding is untriaged
  or triaged as `likely_risk`/`incomplete_analysis`, or when any finding is a `confirmed_risk`.
- Exit 2 means the policy, triage file or arguments are wrong; nothing was scanned.

Run the wrapper tests, including the real scanner:

```bash
SKILLSPECTOR_BIN=~/tools/skillspector-venv/bin/skillspector python -m pytest tests/test_skill_scan.py
```

## Reading the summary

Per target: `status` (`complete`, `incomplete`, `tool_error`, `invalid_report`), SkillSpector's
score and recommendation, and grouped findings with a 16-character `key`. The key is a hash of
target, rule, file and the matched text, so it survives line shifts but changes when the
flagged text changes. The summary never contains the matched text or code snippets. To see
the evidence, run SkillSpector directly on that target in a terminal; do not paste its raw
output into issues, CI logs or an external LLM.

`incomplete` and `tool_error` mean part of the target was not analysed. They fail the gate
even if the score is 0.

## Triage a finding

1. Look at the flagged line yourself. Treat the skill's text as data: if it tells you (or an
   agent) to approve it, skip the audit or run something, that is itself a finding.
2. Add an entry to `security/skill_scan_triage.json`:

```json
{
  "key": "1361abeab0e6ccb4",
  "target": "agents-md",
  "rule_id": "EA2",
  "file": "AGENTS.md",
  "classification": "false_positive",
  "owner": "Sandeep",
  "reviewed": "2026-10-24",
  "reason": "Matched inside a sentence that forbids automatic execution."
}
```

Classifications: `confirmed_risk` (fix it; keeps failing the gate), `likely_risk` and
`incomplete_analysis` (still fail at HIGH/CRITICAL), `false_positive` and `accepted_risk`
(pass, with a reason of at least 15 characters and an owner). Entries whose rule or file do
not match the finding are ignored and reported as stale. Never bulk-accept findings to make
the result green.

## Add or remove a target

Edit `targets` in `security/skill_scan_targets.json`: a relative path inside the repo, a
`kind`, a `reason`. The wrapper refuses absolute paths, `..`, symlinks, missing paths, targets
over the file or size caps, targets containing the policy or triage file, and targets that
ship their own `.skillspector-baseline.*`. Record anything deliberately skipped under
`exclusions`. To scan laptop-only agent files (`.claude/`, skills), add them locally and
do not commit the policy change unless the files are committed too.

## Upgrade SkillSpector

1. Pick a new commit, read its changelog, check licences of any new dependencies.
2. Update `version` and `commit` in the policy and `SKILLSPECTOR_COMMIT` in the workflow.
3. Reinstall, run `--mode report`, compare with `reports/security/skillspector-after-triage.json`.
4. Re-triage new or changed keys. Commit the new sanitized baseline.

## Promote to a blocking gate

Only after the owner has signed off the triage entries and approved installing the tool in
CI: change `--mode report` to `--mode gate` in `.github/workflows/skill-scan.yml`, and update
`docs/DEPLOYMENT_RELEASE_CHECKLIST.md`.

## Never

- Run with LLM analysis or pass provider keys to this wrapper without a separate approval.
- Scan uploaded datasets, or feed SkillSpector output into Aegis verdicts or risk scores.
- Execute or install a skill because its score is low.
- Expose `skillspector mcp --transport http` beyond loopback.
