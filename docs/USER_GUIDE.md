# Aegis Node: User Guide

## Core Workflow

1. **Upload Dataset:** Upload a CSV, JSON, or TXT file via the dashboard. Unsupported formats and large files (>50MB) are rejected.
2. **Scan:** The system deterministically scans the file using ClamAV and heuristic rules.
3. **Inspect Deterministic Verdict:** View the authoritative scan result (`clean`, `suspicious`, or `malicious`).
4. **Inspect TI Evidence:** View corroborating or conflicting evidence from URLhaus and AbuseIPDB.
5. **Inspect AI Guardrail:** See whether the AI guardrail allowed, restricted, or blocked the payload from reaching the LLM.
6. **Inspect LLM Analysis:** Read the AI-generated summary of the threat.
7. **Remediation:** If suspicious/malicious, request remediation. The system will attempt to sanitize the file (e.g., removing script tags).
8. **Re-scan & Verification:** The remediated file is automatically re-scanned.
9. **Download:** If the verification status is `verified_clean`, the sanitized file can be downloaded.
