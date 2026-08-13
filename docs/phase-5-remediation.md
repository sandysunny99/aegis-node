# Aegis Node — Phase 5: Secure Dataset Remediation & Verification

**Primary Project Location**: `C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\`  
**Date**: August 8, 2026  
**Status**: Implementation & Quality Verification Complete (PASS)  

---

## 1. Executive Summary

Phase 5 introduces format-aware, deterministic dataset threat remediation coupled with an automated re-scan verification pipeline:

$$\text{Upload} \longrightarrow \text{Scan} \longrightarrow \text{Detect} \longrightarrow \text{Remediate} \longrightarrow \text{Re-Scan} \longrightarrow \text{Verify Threat Reduction}$$

Every transformation is format-aware, non-destructive, auditable, and preserves original file immutability.

---

## 2. Supported Formats & Transformation Rules

| Threat Category | Rule IDs | Target Format | Remediation Transformation |
|---|---|---|---|
| **Formula Injection** | `FORM-001`, `FORM-002`, `FORM-003` | CSV, JSON | Single-quote prefixing (`'=`): `=CMD(...)` $\rightarrow$ `'=CMD(...)`. Disables formula execution when opened in Excel/Sheets. |
| **Script Injection** | `SCRP-001`, `SCRP-002`, `SCRP-003` | CSV, JSON | Converts `<script>` tags to `[script_removed]`, `javascript:` to `[js_removed]:`, and `eval()`/`exec()` to `[eval_removed]`. |
| **SQL Injection** | `SQLI-001`, `SQLI-002` | CSV, JSON | Neutralizes classic SQL injection patterns (`' OR '1'='1` $\rightarrow$ `[sql_payload_neutralized]`) without executing any SQL or DB connection. |
| **Binary / Null Byte** | `BIN-001` | CSV, JSON, Parquet | Strips null byte control characters (`\x00`). |

---

## 3. Original File Immutability & Storage Isolation

- **Original Upload Storage**: Preserved untouched in `data/samples/{uuid}.{ext}`. Original SHA-256 hash remains unchanged in SQLite.
- **Sanitized Artifact Storage**: Isolated in `data/sanitized/{uuid}_sanitized.{ext}`.
- **SHA-256 Checksumming**: Distinct `sanitized_sha256` computed for the sanitized artifact.
- **Path Traversal Protection**: Enforced strict boundary checks in `FileService.get_sanitized_path()`.

---

## 4. Verification & Metrics Pipeline

Following sanitization, an automated re-scan runs `scanner.engine.run_scan()` on the sanitized artifact.

$$\text{Threat Reduction \%} = \max\left(0.0, \min\left(100.0, \frac{\text{Risk}_{\text{orig}} - \text{Risk}_{\text{san}}}{\text{Risk}_{\text{orig}}} \times 100\right)\right)$$

### Remediation Status Definitions
- `completed`: Re-scan reports 0 remaining threats.
- `partial`: Re-scan reports remaining threats (`remaining_findings_count > 0`). "Remediation Incomplete" notice displayed in UI.
- `failed`: Exception or invalid format during transformation.

---

## 5. API Endpoints

- **`POST /api/v1/datasets/{dataset_id}/remediate`**: Triggers sanitization, re-scan verification, persists `RemediationRecord`, updates dataset status.
- **`GET /api/v1/datasets/{dataset_id}/remediation`**: Retrieves latest remediation report and verification metrics.
- **`GET /api/v1/datasets/{dataset_id}/download-sanitized`**: Secure download of the sanitized artifact (`sanitized_<original_filename>`).

---

## 6. Automated Test Coverage (40/40 PASSED)

```text
tests/test_remediation.py::test_formula_remediation_and_rescan PASSED
tests/test_remediation.py::test_script_remediation_and_rescan PASSED
tests/test_remediation.py::test_sql_remediation_and_rescan PASSED
tests/test_remediation.py::test_clean_dataset_remediation PASSED
tests/test_remediation.py::test_download_sanitized_endpoint_and_path_traversal PASSED

================ 40 passed, 1 warning in 44.39s ================
```

---

## 7. Known Limitations

- **Parquet Format**: Parquet reading/writing supported via pandas/pyarrow; formula escaping applies to string columns. Complex binary column reconstruction deferred.
- **Quarantine Handling**: Quarantined datasets can be remediated from `data/quarantine/` safely; output sanitized files are placed in `data/sanitized/`.
