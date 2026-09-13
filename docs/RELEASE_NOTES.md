# Release Notes: Aegis Node 1.0.0

Aegis Node 1.0.0 represents the final frozen capability baseline. It provides a secure, layered pipeline for dataset scanning and analysis.

## Key Features
- **Deterministic Scanning:** ClamAV and heuristics.
- **TI Enrichment:** URLhaus and AbuseIPDB.
- **AI Analysis:** Contextual assistance bounded by native guardrails.
- **Remediation:** Automated sanitization and re-scan.
- **Observability:** Granular visibility into AI and TI states.

## Security Architecture
Aegis Node does not trust any single layer. It relies on a lookup-only TI model, isolated untrusted boundaries, and deterministic authority. AI probabilistic generation is strictly supervised.

## Validation
Fully validated locally and tested in deployment against Render and Vercel architectures. 

## Known Limitations
Please see `LIMITATIONS.md` for details regarding binary remediation boundaries, LLM dependencies, and guardrail constraints.
