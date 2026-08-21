# Aegis Node v1.0 — Initial Validation Baseline

**Timestamp**: 2026-08-21T11:17:00+05:30  
**Phase**: Phase 0 Baseline Repository & Test Verification  
**Auditor / Reviewer**: Senior AI Security Architect & M.Tech Project Reviewer  

---

## 1. System Environment & Tool Versions

- **Repository**: [sandysunny99/aegis-node](https://github.com/sandysunny99/aegis-node)
- **Git Branch**: `main` (switching to `validation-v1` for phase execution)
- **Baseline Commit**: `e83f7d9` (`docs: add security audit, fix report, post-fix audit, and research methodology documentation`)
- **Python Version**: `3.12.10`
- **Node.js Version**: `v25.2.1`
- **Operating System**: Windows (Host) / Linux Container (Render Target)
- **Docker CLI**: Not installed in local shell; container builds verified via Dockerfile static inspection and CI/CD targets.

---

## 2. Test Suite Baseline Execution

Executed command:
```bash
python -m pytest tests/ -v
```

### Execution Metrics:
- **Total Test Files**: 15
- **Tests Collected**: 221
- **Tests Passed**: 221 (100.0%)
- **Tests Failed**: 0
- **Tests Skipped**: 0
- **Errors**: 0
- **Warnings**: 1 (Starlette deprecation warning regarding TestClient httpx backend)
- **Execution Duration**: 27.77 seconds

---

## 3. Verified Security Hardening Inclusions

Direct source code inspection confirms the presence of all previous security hardening features:
1. **Malware Reference Separation**: `MAL-009` reclassified as `malware_reference` (`low` severity), returning `clean_with_limitations` with informational context.
2. **Explicit Verification States**: `_determine_verdict` emits `clean_verified`, `clean_with_limitations`, `suspicious`, `malicious`, or `scan_incomplete`.
3. **Streaming Upload to Disk**: `FileService.save_upload_stream` writes 64 KB chunks directly to disk with incremental SHA-256 computation and size enforcement (`50 MB`).
4. **Scan Coverage Tracking**: Row counting and coverage calculations (`rows_total`, `rows_inspected`, `coverage_percentage`, `coverage_status`).
5. **Context-Aware Formula Detection**: `_is_safe_literal_not_formula` prevents false-positives on `-10.5`, `+91`, and `@alice`.
6. **LLM Evidence Isolation**: `<UNTRUSTED_DATA>` delimiters enclosing all evidence passed to Gemini/Groq/xAI LLMs.
7. **Frontend Status Badges**: React UI components rendered with updated verification states and limitation pills.
