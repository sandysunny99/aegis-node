# Aegis Node Architecture
## Core Pipeline
1. **Secure Upload & Storage**: Files hashed (SHA-256), sanitized names, UUID storage.
2. **Local Threat Detection**:
   - Stage 1: ClamAV (signature-based).
   - Stage 1.5: YARA (custom pattern matching).
   - Stage 2: Heuristics & Normalization (multi-encoding evasion detection).
3. **External Threat Intelligence (Optional)**:
   - VirusTotal (Hash lookup).
   - URLhaus (Malware URL lookup).
   - AbuseIPDB (Public IP reputation).
4. **Evidence Fusion & LLM**: Synthesize local and external signals for remediation strategy.
5. **Deterministic Remediation**: Safe extraction/cleaning of datasets.
6. **Re-scan & Verification**: Guarantee sanitized output is clean.
