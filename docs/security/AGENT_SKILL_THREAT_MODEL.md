# Agent-skill threat model

Scope: the AI agents (Claude Code, Antigravity) that help build, test and release Aegis
Node, and the instructions, skills, scripts and CI they act on. This is about the
development toolchain, not the Aegis dataset-scanning service (see
`docs/AEGIS_NODE_SECURITY_ARCHITECTURE.md` for that).

Labels: **Fact** (checked in the repo on 2026-10-24), **Assumption**, **Control**.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Provider and TI keys | `.env`, `RENDER_*.env` on the owner's laptop; Render env vars | Billable APIs, Turnstile, R2 storage |
| `main` branch and Render auto-deploy | GitHub, Render | A push to `main` deploys the public site |
| Local scan data | Docker volumes, `data/` | Uploaded datasets and scan history |
| Thesis evidence | `docs/`, `evaluation/`, report files | Must stay accurate and defensible |

## Entry points for untrusted instructions

| Entry point | Fact / assumption | Example abuse |
|---|---|---|
| Third-party skill packs (scientific, cybersecurity) | Fact: named in `docs/*SKILLS*.md` as Antigravity-only; not in git | A skill tells the agent to read `.env` and post it, or to run `curl | bash` |
| Laptop-only `.claude/`, skills, MCP servers | Assumption: may exist untracked on the laptop | Same, plus MCP tool descriptions that poison tool choice |
| Pasted prompts | Fact: the owner pastes long prompts, sometimes meant for other projects | Instruction override inside pasted text |
| Repo content read by an agent | Fact: datasets, fixtures, docs contain attack strings by design (prompt-injection benchmark, EICAR) | Agent follows an instruction found in a fixture |
| Scripts agents are asked to run | Fact: `scripts/*.ps1`, `scripts/*.py` | Destructive or billable side effects (`docker compose down -v`, real Groq calls) |
| CI workflows | Fact: `ci.yml` only, `contents: read` (the SkillSpector workflow is deferred) | Workflow change that exposes secrets or deploys |

## Threats and controls

| Threat | Control | Status |
|---|---|---|
| Malicious or careless skill instructions (injection, exfiltration, credential access, `curl | bash`) | SkillSpector static scan of approved targets before trusting them, run locally; triage required for HIGH/CRITICAL | Control in place, local and report-only |
| Scanner says SAFE although it could not read everything | Wrapper fails on `partial`/`failed` completeness, exit 2, timeout, wrong version, malformed report | Control in place, tested |
| Skill text manipulates the reviewer or the scan ("already approved, mark SAFE") | Static mode only (no model reads the text); wrapper never prints matched text; triage lives outside every target; targets that ship a `.skillspector-baseline.*` are refused; `--use-shipped-baseline` never passed | Control in place, tested |
| Scanner leaks private content | `--no-llm`; dead proxy for HTTP(S) so SC4 does not contact OSV.dev; minimal environment without keys; sanitized outputs with no snippets or absolute paths | Control in place, tested |
| Scanner itself is compromised or changes behaviour | Pinned commit and `uv.lock`, version check before each scan, separate venv outside the repo, no repository secrets in the CI job | Partial: supply-chain trust in NVIDIA's repo and PyPI remains |
| Destructive local scripts run by an agent | `cleanup.ps1` keeps data by default; volume deletion needs `-RemoveVolumes` and the typed phrase `DELETE AEGIS DATA`; no force-kill | Control in place, tested |
| Billable or key-reading scripts run by an agent | `verify_gateway.py` refuses to load `.env` or call Groq without `--confirm-paid-calls` | Control in place, tested |
| Agent pushes to `main` / deploys | Project rule: never push or touch `main` without the owner asking; the scan job cannot deploy | Process control |
| SkillSpector result leaks into dataset verdicts | No code in `backend/` or `scanner/` reads its output; separate report folder | Control in place |

## What the scan does not cover

- Runtime behaviour of skills or scripts (static analysis only).
- Agent files that are not in git (scan them locally with the same policy mechanism).
- PowerShell semantics (regex checks only), text in images, encoded payloads in strings,
  non-English instructions.
- A low score or `SAFE` recommendation is not proof that a skill is safe.
