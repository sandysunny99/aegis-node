# Changelog

## [1.0.0] - Aegis Node Final Release

### Major Capabilities
- Full-stack security pipeline for structured datasets (CSV/JSON/TXT).
- Deterministic scanning via ClamAV and heuristic rules.
- Threat Intelligence fusion via URLhaus and AbuseIPDB.
- AI-assisted threat analysis via Cloudflare AI Gateway.
- Automated remediation and mandatory verification re-scanning.

### Security Architecture
- Lookup-only TI bounding to prevent SSRF.
- Native AI guardrails for prompt-injection defense.
- Absolute isolation of uploaded content (zero execution).
- Deterministic authority over AI probabilistic generation.

### Observability
- Granular UI tracking for Guardrail state (ALLOW/RESTRICT/BLOCK).
- TI Provenance and Conflict resolution tracking.

### Validation
- Validated via 319 regression tests and full Phase 11 production matrix.

### Known Limitations
- Remediation is limited to supported structural formats (binary files are blocked at upload).
- Guardrail evaluations are synthetically constrained (80% holdout detection / 20% FPR).
