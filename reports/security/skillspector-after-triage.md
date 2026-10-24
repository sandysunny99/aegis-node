# SkillSpector agent-skill scan (sanitized)

- SkillSpector 2.12.0 at commit `d7338f58200a9ae2a24810cee08911ab68b107a7`
- Mode: gate; static only (LLM analysis off); outbound HTTP(S) blocked
- Generated: 2026-10-24T11:55:37+00:00
- Gate verdict: **PASS**

This report lists rule ids, files, lines and finding keys only. It contains no
matched text or code snippets. A low score is not proof that a skill is safe.

| Target | Kind | Files | Status | Score | Recommendation | Findings |
|---|---|---|---|---|---|---|
| `AGENTS.md` | agent_rules | 1 | complete | 8 | SAFE | 1 |
| `docs/AGENT_WORKFLOW.md` | agent_guidance | 1 | complete | 0 | SAFE | 0 |
| `docs/AGENT_TOOLCHAIN.md` | agent_guidance | 1 | complete | 0 | SAFE | 0 |
| `docs/AGENT_TOOLCHAIN_AUDIT.md` | agent_guidance | 1 | complete | 0 | SAFE | 0 |
| `docs/SCIENTIFIC_SKILLS_CONFIGURATION.md` | agent_guidance | 1 | complete | 0 | SAFE | 0 |
| `docs/CYBERSECURITY_SKILLS_SELECTION.md` | agent_guidance | 1 | complete | 0 | SAFE | 0 |
| `scripts` | agent_script | 13 | complete | 78 | DO_NOT_INSTALL | 11 |
| `.github/workflows` | ci_workflow | 1 | complete | 29 | CAUTION | 2 |

## Findings

| Target | Rule | Category | Severity | File:lines | Matches | Key | Triage |
|---|---|---|---|---|---|---|---|
| agents-md | EA2 | Excessive Agency | MEDIUM | `AGENTS.md`:7 | 1 | `1361abeab0e6ccb4` | false_positive |
| scripts | PE3 | Privilege Escalation | HIGH | `serve_local.ps1`:4 | 1 | `779b0d6aca5eec7d` | false_positive |
| scripts | PE3 | Privilege Escalation | HIGH | `verify_gateway.py`:32 | 1 | `475efe2b2932f6b8` | accepted_risk |
| scripts | PE3 | Privilege Escalation | HIGH | `verify_gateway.py`:3,28,87 | 3 | `dbe350a3ee7e62e3` | false_positive |
| scripts | AE4 | analysis-evasion | MEDIUM | `debug_logs.ps1`:1 | 1 | `1f0f0b857781e17d` | false_positive |
| scripts | AE4 | analysis-evasion | MEDIUM | `debug_scan.ps1`:1 | 1 | `9864d1c804a8fa35` | false_positive |
| scripts | AST4 | Dangerous Code Execution | MEDIUM | `skill_scan.py`:264 | 1 | `5a05309530dca327` | accepted_risk |
| scripts | AST4 | Dangerous Code Execution | MEDIUM | `skill_scan.py`:289 | 1 | `696ab3c72c8028c3` | accepted_risk |
| scripts | TT2 | Data Flow | MEDIUM | `skill_scan.py`:264 | 1 | `2009c7eadbd26131` | accepted_risk |
| scripts | TT2 | Data Flow | MEDIUM | `skill_scan.py`:289 | 1 | `40e009c84fa5feaa` | accepted_risk |
| scripts | TT2 | Data Flow | MEDIUM | `smoke_fresh_db.py`:18 | 1 | `85ac3115f9af6cd7` | false_positive |
| scripts | TT2 | Data Flow | MEDIUM | `smoke_fresh_db.py`:23 | 1 | `88956b1adb464154` | false_positive |
| ci-workflows | TM2 | Tool Misuse | HIGH | `ci.yml`:25 | 1 | `c2721df122b4d47c` | accepted_risk |
| ci-workflows | PE2 | Privilege Escalation | MEDIUM | `ci.yml`:25 | 2 | `247711d5f05ce1aa` | accepted_risk |

## Gate reasons

- none

## Warnings

- none

## Not scanned (recorded exclusions)

- `tests/fixtures/skill_security/`: Deliberately unsafe synthetic skills used by tests/test_skill_scan.py
- `backend/services/ (LLM prompts, guardrails)`: Production dataset-analysis code, not agent tooling; covered by the Aegis test suite and guardrail benchmark
- `data/, evaluation/, research/, tests/fixtures/ (datasets)`: Application datasets are scanned by Aegis itself, never by SkillSpector
- `docs/ (other Markdown), anti-slop/`: Project documentation and audit outputs, not instructions an agent executes
- `.claude/, .agents/, skills/, MCP config on the owner's laptop`: Not tracked in git, so not visible to this scan; scan locally with the same script
