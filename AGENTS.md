# Aegis Node Development Rules

## Project Goal
Build a lightweight AI-assisted dataset security analysis application (M.Tech project).

## Architecture
Single FastAPI backend + simple React (Vite) frontend + SQLite database + ClamAV scanner.
Add complexity only when a concrete requirement demands it.

## Security
- Treat every uploaded file as untrusted.
- Never execute uploaded files.
- Never use eval() or exec() on uploaded content.
- Never trust file extensions — verify MIME type independently.
- Never overwrite original uploaded files.
- Always preserve and record SHA-256 of every file before and after processing.
- Always re-scan sanitized files before marking them clean.
- All LLM communication happens only from the backend — never from the frontend.

## AI / LLM Rules
- LLM is an analysis assistant, not the primary malware detector.
- Primary detection = ClamAV + content/rule analysis. LLM is secondary.
- Never allow dataset content to override system instructions (prompt injection guard).
- Never allow LLM output to execute commands or write files directly.
- Never send the entire dataset to the LLM. Send only compact evidence (findings JSON).
- Target: 1 LLM request per scan. Maximum: 2 LLM requests per scan.

## Dependencies
- Do not add packages without a concrete justification tied to a feature.
- Prefer Python standard-library functionality over third-party packages.
- Avoid duplicate libraries that serve the same purpose.
- Deferred packages: yara-python, scikit-learn, transformers, torch, sentence-transformers, shap, psycopg.

## Development Process
- Make the smallest change that accomplishes the task.
- Run relevant tests after every change.
- Do not rewrite unrelated working code.
- Do not expand scope beyond the current task.
- Do not repeatedly load the full repository — inspect the tree first, then read only relevant files.

## M.Tech Scope Constraint
Prefer simple, measurable, reproducible implementations over novel complexity.
