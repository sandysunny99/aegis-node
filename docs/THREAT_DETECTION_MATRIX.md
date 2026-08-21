# Aegis Node — Comprehensive Threat Detection Matrix

**Project**: Aegis Node: An AI-Assisted Framework for Secure Dataset Threat Detection and Remediation  
**Classification**: M.Tech Cybersecurity Threat Coverage Specification  

---

## 1. Threat Detection, Explanation, and Remediation Capabilities

The following matrix documents the implemented security stages for each category of dataset threat:

| Threat Category | Primary Detection Layer | Rule IDs / Signatures | AI Contextual Reasoning | Remediation Strategy | Post-Remediation Re-Scan Verification |
|---|---|---|---|---|---|
| **Malware Artifacts** | Stage 0 (Raw Bytes) + Stage 1 (ClamAV) | `MAL-001` (EICAR), `MAL-002` (PE MZ), `MAL-003` (ELF), `MAL-005` (PowerShell Dropper), `MAL-006` (IEX cradle), `MAL-007` (Reverse Shell) | Explains artifact origin, risk profile, and deployment context. | Payload string neutralized to `[REMOVED]` in sanitized copy. | Verified clean ($R_{\text{san}} = 0.0$). |
| **Malware Research Reference** | Stage 2 (Content Checker) | `MAL-009` (Family Names: WannaCry, Mirai, LockBit, Emotet, etc.) | Explains that text represents legitimate research metadata. | **Preserved intact** (No destructive wiping). | Verified `CLEAN_WITH_LIMITATIONS` (`MALWARE_REFERENCE_ONLY`). |
| **Spreadsheet Formula Injection (CSV/DDE)** | Stage 2 (Content Checker) | `FORM-001` (Excel formula syntax), `FORM-002` (DDE command pipe), `FORM-003` (HYPERLINK) | Analyzes exfiltration and execution risk. | Prepends single quote (`'`) to disable Excel evaluation while preserving data readability. Safe literals (`-10.5`, `+91`, `@handle`) are untouched. | Verified clean ($R_{\text{san}} = 0.0$). |
| **Script Injection (XSS)** | Stage 2 (Content Checker) | `SCRP-001` (`<script>`), `SCRP-002` (`javascript:`), `SCRP-003` (`eval()`) | Evaluates browser execution and session hijacking risk. | Replaces active tag with `[script_removed]`. | Verified clean ($R_{\text{san}} = 0.0$). |
| **SQL Injection (SQLi)** | Stage 2 (Content Checker) | `SQLI-001` (`' OR '1'='1`), `SQLI-002` (`UNION SELECT`) | Identifies backend database manipulation payloads. | Neutralizes SQL injection tokens. | Verified clean ($R_{\text{san}} = 0.0$). |
| **Adversarial Prompt Injection** | Architectural Isolation | Delimited within `<UNTRUSTED_DATA>` | Treated strictly as passive input data; system instructions forbid command execution. | Optional (User review). | Protected against LLM hijacking. |
| **Obfuscated Payloads** | Stage 2 Preprocessor | URL Decode, HTML Entity Unescape, SQL Comment Strip, Whitespace Normalization | Exposes hidden payloads for scanner inspection. | Strips deobfuscated payload. | Re-scanned and verified. |
| **Binary Anomalies / High Entropy** | Stage 0.5 (Heuristic Scanner) | `HEUR-001` (Entropy > 7.5), `HEUR-002` (Non-printable byte ratio), `HEUR-003` (Injection APIs: VirtualAlloc, CreateRemoteThread) | Flags hidden encrypted or compiled segments in tabular fields. | Flagged for security analyst quarantine. | Verified. |
| **Structural Corruption** | Load Boundary | Safe parser exception handler | Reports dataset parsing error without crashing runtime. | Retains unparseable lines. | Marked as `SCAN_INCOMPLETE`. |

---

## 2. Invariant Security Principles

1. **Deterministic Authority**: All security verdicts (`CLEAN_VERIFIED`, `CLEAN_WITH_LIMITATIONS`, `SUSPICIOUS`, `MALICIOUS`, `SCAN_INCOMPLETE`) are calculated deterministically by backend scanner logic. The LLM cannot override or downgrade scanner findings.
2. **Provenance Preservation**: The original uploaded file is immutable on disk. Remediation produces a separate sanitized file with its own SHA-256 hash.
3. **Mandatory Verification**: No remediation is reported as successful without executing a mandatory second scan of the sanitized artifact.
