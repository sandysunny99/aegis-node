# Aegis Node — Security Audit Report

**Date**: August 2026  
**Auditor**: Senior Cybersecurity Architect & Full-Stack Security Auditor  
**Target Repository**: [sandysunny99/aegis-node](https://github.com/sandysunny99/aegis-node)  
**Classification**: Academic / M.Tech Cybersecurity Research Project  

---

## 1. Executive Summary

This document presents the findings from an exhaustive, code-level read-only security audit of the Aegis Node codebase. The application was audited across all layers: raw binary ingestion, multi-stage detection engine (ClamAV, Heuristics, Content Rules), LLM contextual reasoning, deterministic remediation, database transactions, REST API security, container hardening, and cloud deployment boundaries.

---

## 2. Security Findings Summary Table

| Finding ID | Severity | Category | Target File(s) | Status | Root Cause |
|---|---|---|---|---|---|
| **FINDING-001** | P0 (Critical) | Classification | `scanner/content_checker.py`, `scanner/engine.py` | **CONFIRMED** | `MAL-009` matched malware names (`WannaCry`, `LockBit`) with critical severity, falsely flagging research text as active malware. |
| **FINDING-002** | P0 (Critical) | Verification Model | `scanner/engine.py`, `backend/schemas.py` | **CONFIRMED** | Scanner returned `verdict = "clean"` even when ClamAV daemon was offline or in mock mode. |
| **FINDING-003** | P0 (Critical) | Upload DoS / Memory | `backend/routers/datasets.py`, `file_service.py` | **CONFIRMED** | In-memory `bytearray` buffering of uploads up to 500 MB caused high RAM usage and OOM crash risk on Render (512MB RAM). |
| **FINDING-004** | P1 (High) | Verification Integrity | `scanner/content_checker.py`, `engine.py` | **CONFIRMED** | Truncating scans at 10,000 rows without reporting total rows or coverage percentage presented partial scans as complete scans. |
| **FINDING-005** | P1 (High) | Post-Remediation Verification | `backend/routers/remediation.py` | **CONFIRMED** | Remediation only recorded binary `"completed"` vs `"partial"` without verifying if second scan had limitations or residual risks. |
| **FINDING-006** | P1 (High) | Research Data Destruction | `scanner/sanitizer.py` | **CONFIRMED** | `_remediate_malware_cell` wiped text fields containing malware keywords (`[REMOVED]`), destroying research metadata. |
| **FINDING-011** | P1 (High) | False Positive Injection | `scanner/content_checker.py`, `sanitizer.py` | **CONFIRMED** | `FORM-001` treated all leading `-`, `+`, `@` indiscriminately as formula injection, falsely flagging `-10.5`, `+91`, and `@alice`. |
| **FINDING-013** | P2 (Medium) | AI Prompt Injection | `backend/services/llm_service.py` | **CONFIRMED** | Scanner evidence was not enclosed in structured `<UNTRUSTED_DATA>` tags to enforce strict data-vs-instruction separation. |
| **FINDING-016** | P2 (Medium) | API CORS Configuration | `render.yaml`, `backend/config.py` | **PARTIALLY VALID** | `render.yaml` configured wildcard `*` for `ALLOWED_ORIGINS` which is overly broad for production environments. |
| **FINDING-019** | P3 (Low) | Container Hardening | `Dockerfile` | **ALREADY FIXED** | Verified non-root user `aegis` (UID 10001) and multi-stage Node/Python build are implemented. |
| **FINDING-020** | P3 (Low) | Database Transaction Rollback | `backend/database.py` | **ALREADY FIXED** | WAL mode, pragma normal, and `get_db` rollback/close are correctly configured. |

---

## 3. Detailed Finding Analyses

### FINDING-001: Malware Metadata Reference vs Active Malware Artifact
- **Severity**: P0 (Critical)
- **Component**: `scanner/content_checker.py`, `scanner/engine.py`
- **Impact**: Any legitimate research dataset (e.g. classification datasets with columns `label: "WannaCry"` or text descriptions) produced an active `MALICIOUS` verdict and quarantined the dataset.
- **Root Cause**: Rule `MAL-009` was assigned `critical` severity. In `_determine_verdict`, any `critical` finding unconditionally forced `verdict = "malicious"`.
- **Remediation**: Split observations into `MALWARE_REFERENCE` (informational/low severity metadata) and `MALWARE_ARTIFACT` (executable droppers, shellcode, EICAR). Metadata mentions now produce `clean_with_limitations` with a `MALWARE_REFERENCE_ONLY` note.

### FINDING-002: ClamAV Failure Semantics & Silent Degradation
- **Severity**: P0 (Critical)
- **Component**: `scanner/engine.py`
- **Impact**: When the ClamAV daemon is unreachable, the scanner silently skipped antivirus scanning and reported the dataset as verified `clean`, giving a false sense of security.
- **Root Cause**: Default verdict logic lacked explicit verification states.
- **Remediation**: Implemented 6 distinct states: `CLEAN_VERIFIED`, `CLEAN_WITH_LIMITATIONS`, `SUSPICIOUS`, `MALICIOUS`, `SCAN_INCOMPLETE`, `QUARANTINED`. Offline ClamAV now forces `clean_with_limitations` and records `CLAMAV_UNAVAILABLE`.

### FINDING-003: Upload In-Memory Buffering (DoS / OOM Vulnerability)
- **Severity**: P0 (Critical)
- **Component**: `backend/routers/datasets.py`, `backend/services/file_service.py`
- **Impact**: Simultaneous moderate uploads exhausted the 512MB RAM budget of Render free tier instances.
- **Root Cause**: `upload_dataset` accumulated chunks into `bytearray` in memory before writing to disk.
- **Remediation**: Implemented `save_upload_stream` which writes 64 KB chunks directly to temporary files on disk, computes SHA-256 incrementally, and enforces `MAX_UPLOAD_SIZE_MB` (default 50 MB) on the fly.

### FINDING-011: Context-Insensitive Formula Injection False Positives
- **Severity**: P1 (High)
- **Component**: `scanner/content_checker.py`, `scanner/sanitizer.py`
- **Impact**: Benign financial datasets with negative balances (`-10.5`), international phone codes (`+91 9876543210`), and Twitter handles (`@alice`) were corrupted by sanitizer prepending single quotes (`'`).
- **Root Cause**: `FORM-001` used regex `^\s*[=+\-@|]` without checking for numeric or handle literals.
- **Remediation**: Added `_is_safe_literal_not_formula` pre-checks. Formula detection now only flags genuine formula syntax (`=HYPERLINK`, `=CMD`, `=SUM`, `=1+1`, `@SUM`, `+1+1`).
