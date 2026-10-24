# SkillSpector agent-skill scan (sanitized)

- SkillSpector 2.12.0 at commit `d7338f58200a9ae2a24810cee08911ab68b107a7`
- Mode: report; static only (LLM analysis off); outbound HTTP(S) blocked
- Generated: 2026-10-24T11:29:35+00:00
- Gate verdict: **FAIL** (report-only: not blocking)

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
| `scripts` | agent_script | 13 | complete | 73 | DO_NOT_INSTALL | 10 |
| `.github/workflows` | ci_workflow | 2 | complete | 29 | CAUTION | 2 |

## Findings

| Target | Rule | Category | Severity | File:lines | Key | Triage |
|---|---|---|---|---|---|---|
| agents-md | EA2 | Excessive Agency | MEDIUM | `AGENTS.md`:7 | `1361abeab0e6ccb4` | untriaged |
| scripts | PE3 | Privilege Escalation | HIGH | `serve_local.ps1`:4 | `779b0d6aca5eec7d` | untriaged |
| scripts | PE3 | Privilege Escalation | HIGH | `verify_gateway.py`:13 | `475efe2b2932f6b8` | untriaged |
| scripts | AE4 | analysis-evasion | MEDIUM | `debug_logs.ps1`:1 | `1f0f0b857781e17d` | untriaged |
| scripts | AE4 | analysis-evasion | MEDIUM | `debug_scan.ps1`:1 | `9864d1c804a8fa35` | untriaged |
| scripts | AST4 | Dangerous Code Execution | MEDIUM | `skill_scan.py`:260 | `5a05309530dca327` | untriaged |
| scripts | AST4 | Dangerous Code Execution | MEDIUM | `skill_scan.py`:285 | `696ab3c72c8028c3` | untriaged |
| scripts | TT2 | Data Flow | MEDIUM | `skill_scan.py`:260 | `2009c7eadbd26131` | untriaged |
| scripts | TT2 | Data Flow | MEDIUM | `skill_scan.py`:285 | `40e009c84fa5feaa` | untriaged |
| scripts | TT2 | Data Flow | MEDIUM | `smoke_fresh_db.py`:18 | `85ac3115f9af6cd7` | untriaged |
| scripts | TT2 | Data Flow | MEDIUM | `smoke_fresh_db.py`:23 | `88956b1adb464154` | untriaged |
| ci-workflows | TM2 | Tool Misuse | HIGH | `ci.yml`:25 | `c2721df122b4d47c` | untriaged |
| ci-workflows | PE2 | Privilege Escalation | MEDIUM | `ci.yml`:25 | `247711d5f05ce1aa` | untriaged |

## Gate reasons

- scripts: PE3 in serve_local.ps1:4 is untriaged HIGH
- scripts: PE3 in verify_gateway.py:13 is untriaged HIGH
- ci-workflows: TM2 in ci.yml:25 is untriaged HIGH

## Warnings

- agents-md: EA2 in AGENTS.md:7 is untriaged MEDIUM
- scripts: AE4 in debug_logs.ps1:1 is untriaged MEDIUM
- scripts: AE4 in debug_scan.ps1:1 is untriaged MEDIUM
- scripts: AST4 in skill_scan.py:260 is untriaged MEDIUM
- scripts: AST4 in skill_scan.py:285 is untriaged MEDIUM
- scripts: TT2 in skill_scan.py:260 is untriaged MEDIUM
- scripts: TT2 in skill_scan.py:285 is untriaged MEDIUM
- scripts: TT2 in smoke_fresh_db.py:18 is untriaged MEDIUM
- scripts: TT2 in smoke_fresh_db.py:23 is untriaged MEDIUM
- ci-workflows: PE2 in ci.yml:25 is untriaged MEDIUM

## Not scanned (recorded exclusions)

- `tests/fixtures/skill_security/`: Deliberately unsafe synthetic skills used by tests/test_skill_scan.py
- `backend/services/ (LLM prompts, guardrails)`: Production dataset-analysis code, not agent tooling; covered by the Aegis test suite and guardrail benchmark
- `data/, evaluation/, research/, tests/fixtures/ (datasets)`: Application datasets are scanned by Aegis itself, never by SkillSpector
- `docs/ (other Markdown), anti-slop/`: Project documentation and audit outputs, not instructions an agent executes
- `.claude/, .agents/, skills/, MCP config on the owner's laptop`: Not tracked in git, so not visible to this scan; scan locally with the same script
