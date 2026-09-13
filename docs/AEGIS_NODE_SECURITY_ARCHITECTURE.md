# Aegis Node: Security Architecture

## Core Philosophy
**The system does not trust any single security layer.** Aegis relies on defense-in-depth, utilizing deterministic scanning, threat intelligence, and AI analysis, while isolating them to prevent cascading failures.

## Security Boundaries & Controls

1. **Untrusted Dataset Boundary**
   - Files are validated by MIME type, extension, and size limits upon upload.
   - **No Execution:** The system NEVER executes or detonates uploaded content. Static analysis only.

2. **Deterministic Scanning (The Authority)**
   - SHA-256 hashing uniquely identifies all artifacts.
   - ClamAV and heuristic regex/anomaly scanners (YARA-style) form the baseline truth.

3. **Threat Intelligence Lookup-Only Model**
   - TI lookups (URLhaus, AbuseIPDB) extract indicators from evidence but perform **bounded lookups** only.
   - **No Active Probing:** The system never fetches attacker URLs or probes IPs.

4. **Threat Intelligence Fusion**
   - Evidence is normalized. Conflicts between local scans and TI are surfaced explicitly (`CONFLICTED` state).

5. **Prompt-Injection Defense**
   - Native guardrails evaluate the payload.
   - Outcomes: `ALLOW` (proceed), `RESTRICT` (send limited context), `BLOCK` (bypass LLM entirely).

6. **Output Validation & Action Controls**
   - LLM output is structurally validated (JSON Schema).
   - LLM cannot change the deterministic verdict.

7. **Remediation & Mandatory Re-scan (Verification)**
   - Remediated files are hashed and forced through a mandatory re-scan.
   - The original threat verdict is never retroactively modified; verification is a separate state.

8. **Failure & Secret Isolation**
   - Secrets are isolated strictly server-side.
   - Provider failures (TI or LLM) result in graceful fallback to local deterministic verdicts.
