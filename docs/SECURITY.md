# Aegis Node: Security Policy

## Supported Security Boundaries
- **No Execution:** Aegis Node will NEVER execute, evaluate, or detonate uploaded content.
- **Bounded Lookup:** TI integrations will NEVER actively probe or fetch malicious infrastructure.
- **Deterministic Authority:** AI layers will NEVER override deterministic security verdicts.
- **Secret Isolation:** API keys and provider credentials must remain strictly server-side.

## Unsafe Use Warnings
- Aegis Node is designed for static analysis of datasets. It is NOT a dynamic sandbox.
- Do not bypass the `/upload` MIME restrictions to force binary processing through the remediation pipeline.

## Secrets Handling
Never commit `.env` files or API keys. 

## Responsible Disclosure
If you identify a boundary violation (e.g., SSRF bypass in TI layers or execution of uploaded content), please report it responsibly to the repository maintainers. Do not publish sensitive internal infrastructure details.
