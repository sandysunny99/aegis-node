# Aegis Node pipeline map (Phase A)

Mapped from the code at `c895a6b` (tip of `origin/sandysunny99-clamav-pipeline-verification`), not from the docs. Line numbers refer to that commit. Evidence from the Phase A local run is in the "Observed" column; that run used a local uvicorn server with ClamAV unreachable and all outbound HTTP pointed at a dead local proxy (Docker was not running).

## 1. Stages, upload to verdict

| # | Stage | Module / function | Inputs | Outputs | Status values produced | Config flags | Failure behaviour | Tests covering it |
|---|---|---|---|---|---|---|---|---|
| 0 | Bot check | `utils/turnstile.py: verify_turnstile_token` via `routers/datasets.py:62` | `X-Turnstile-Token` header, client IP | bool | 403 "Bot verification unavailable." | `CLOUDFLARE_TURNSTILE_SECRET_KEY`, `APP_ENV` | No secret: bypass in dev, deny in production. Siteverify error: deny | `test_turnstile.py` (6) |
| 0 | API key guard | `utils/auth.py: require_api_key` on every dataset route | `X-API-Key` | pass / 401 | 401 | `API_KEY` (empty = open) | Empty key = open access | `test_security*.py` |
| 1 | Extension allow-list | `file_service.validate_extension` (`datasets.py:71`) | filename | bool | 415 | `allowed_extensions` (csv, parquet, json, jsonl, xlsx, txt) | Reject | `test_upload.py`, `test_api.py` |
| 2 | Streamed save + SHA-256 + size cap + magic bytes | `file_service.save_upload_stream` (`file_service.py:168`) | upload stream | stored file, sha256, mime (from extension), format | 413, 400 (PE/ELF/Mach-O header, bad parquet header, storage failure) | `MAX_UPLOAD_SIZE_MB`, `R2_ENABLED` | Temp file removed on any error | `test_upload.py`, `test_storage.py` |
| 3 | DB record | `DatasetRecord` (`datasets.py:94`) | meta | row, `status=uploaded` | `uploaded` | `DATABASE_URL` | n/a | `test_api.py` |
| 4 | Scan lock | atomic `UPDATE ... WHERE status != 'scanning'` (`datasets.py:145`) | dataset id | `status=scanning` | 409 if already scanning or already remediated | n/a | Remediated rescan sets `status=error` before 409 (gap #4) | `test_api.py` |
| 5 | SHA-256 recompute | `engine._compute_sha256` (`scanner/engine.py:126`) | file | sha256 | n/a | n/a | Raises → 500, `status=error` | `test_e2e_security_pipeline::test_hash_provenance_integrity` |
| 6 | Heuristics (Stage 0.5) | `scanner/heuristics.py: heuristic_scan` | first 1 MB | HEUR-001..008 findings, risk 0–1 | contributes to verdict | `ENABLE_HEURISTICS` (read via `os.getenv`, not settings) | Unreadable file → no findings, no limitation. HEUR-007 needs libmagic, PE-import check needs `pefile` (not in requirements): both skip silently | `test_heuristics.py` (33) |
| 7 | AV (Stage 1) | `services/av_providers/factory.get_av_provider().scan_file` → `ClamAVRestProvider` (`clamav.py:79`) | file (multipart to clamav-rest) | `AVScanResult` | `clamav_status` = clean / infected / skipped | `AV_PROVIDER`, `CLAMAV_API_URL`, `CLAMAV_MOCK_MODE` | Unreachable / bad JSON → `available=False`, `CLAMAV_UNAVAILABLE` limitation, 5 s offline cache | `test_clamav_rest_provider.py` (8) |
| 7b | AV alt | `MetaDefenderProvider` (`metadefender.py:54`) | **whole file uploaded** to MetaDefender Cloud | `AVScanResult` | same | `AV_PROVIDER=metadefender` | same | none found |
| 8 | YARA (Stage 1.5) | `scanner/yara_scanner.py` (yara-python, 4 rule files in `backend/rules/yara/`) | first 2 MB | YARA-xxx findings | contributes | `ENABLE_YARA` exists in config but is never read | Import/compile failure → `is_available=False` or no rules, silently returns `[]`, no limitation | `test_scanner_rules.py`, `test_real_samples.py` |
| 9 | Raw byte scan (Stage 0 inside content check) | `content_checker.raw_bytes_scan` | whole file bytes | MAL-001 (EICAR, critical), MAL-002/003 (PE/ELF), MAL-011 (NOP sled) | contributes | none | n/a | `test_eicar_audit.py`, `test_scanner.py` |
| 10 | Content rules (Stage 2) | `content_checker.check_file` + `_check_string_value` (rules FORM-001..003, SCRP-001..003, SQLI-001..002, MAL-001..011), `normalizer.normalize_text` for de-obfuscation | parsed dataframe, max 10,000 rows (TXT 10,000 lines, XLSX ≤50 MB) | findings, rows_inspected, rows_total, coverage | `coverage_status` FULL / PARTIAL / UNKNOWN; limitations `PARTIAL_DATASET_SCAN`, `PARSER_LIMITATION` | `ENABLE_ENCODING_NORMALIZATION` exists but is never read | Parse error → early return with `PARSER_LIMITATION` | `test_scanner_rules.py`, `test_normalizer.py`, `test_scanner.py` |
| 11 | Local verdict | `engine._determine_verdict` (`engine.py:135`) | AV, content, heuristic, YARA results | verdict, risk 0–10, limitations | `malicious`, `suspicious`, `clean_with_limitations`, `clean_verified`, `scan_incomplete` | none | see rules below | `test_e2e_security_pipeline::test_security_verdict_authority`, `test_scanner.py` |
| 12 | VirusTotal hash lookup (Phase 9.1) | `threat_intelligence/virustotal.lookup_file_hash` (`datasets.py:178`) | SHA-256 only | `ThreatIntelResult`, appended as a `vt_<status>` **finding** | adds `CONFLICT_VT_MALICIOUS`, `VT_UNAVAILABLE_<status>` limitations; never changes verdict | `ENABLE_VIRUSTOTAL` (default **true**, see gap #7), `VIRUSTOTAL_API_KEY` | timeout / 429 / 5xx → limitation; 401/403 → finding only, no limitation | `test_virustotal.py` (9) |
| 13 | URL / IP extraction | regex over full raw bytes (`datasets.py:222-272`), first 5 URLs and 5 IPs (set order) | file bytes | indicators | n/a | n/a | n/a | `test_security_hardening.py` |
| 14 | URLhaus lookup | `threat_intelligence/urlhaus.lookup_url` | URL string only, POST to fixed URLhaus API | `NormalizedTIEvidence` | reputation malicious / benign / unknown | `ENABLE_URLHAUS` (default **true**), `URLHAUS_AUTH_KEY` | 401/403/429/timeout/other → `error_status` | `test_urlhaus.py` (13) |
| 15 | AbuseIPDB lookup | `threat_intelligence/abuseipdb.lookup_ip` | public IPs only (`ip.is_global`) | `NormalizedTIEvidence` | malicious (≥80) / suspicious / benign | `ENABLE_ABUSEIPDB` (default **true**), `ABUSEIPDB_API_KEY` | as above, plus 5xx | `test_abuseipdb.py` (12) |
| 16 | TI fusion (Phase 9.4) | `threat_intelligence/fusion.fuse_reports`, `evaluate_local_verdict_conflict` | evidence list, `providers_checked` (hard-coded `["urlhaus","abuseipdb"]`) | `TIFusionReport` | status active / degraded / error / disabled; strength NONE / SINGLE_PROVIDER / CORROBORATED / CONFLICTED / PROVIDER_UNAVAILABLE; `CONFLICT_TI_MALICIOUS` | none | Exception → `THREAT_INTEL_FUSION_FAILURE` limitation, `threat_intel` null | `test_ti_fusion.py` (9) |
| 17 | Dataset status | `datasets.py:329-336` | verdict | `DatasetRecord.status` | `quarantined` (file moved to `quarantine/`), `suspicious`, else **`clean`** | none | `clean_with_limitations` and `scan_incomplete` both stored as `clean` (gap #1) | none for this mapping |
| 18 | Persist report | `ScanReportRecord` (`datasets.py:344`) | result | row with findings, limitations, TI JSON | n/a | n/a | n/a | `test_api.py` |
| 19 | AI analysis (manual) | `POST /{id}/analyse` → `llm_service.analyse` → `_build_compact_evidence` → `guardrails.evaluate_input_guardrail` → provider chain | latest report's findings, ClamAV status, risk score (not the verdict, limitations or TI) | `LlmAnalysisRecord` | AI status completed / failed / unavailable; AI verdict clean / suspicious / high_risk / inconclusive; guardrail ALLOW / RESTRICT / BLOCK | `AI_PROVIDER`, `AI_FALLBACK_CHAIN`, `AI_GATEWAY_ENABLED`, provider keys | Stored separately; never touches the scan verdict | `test_llm*.py`, `test_ai_fallback.py`, `test_fallback_chain.py`, `test_cloudflare_provider.py`, `tests/benchmark_guardrails.py` |
| 20 | Remediation | `POST /{id}/remediate` → `scanner/sanitizer.sanitize_file` → `file_service.save_sanitized` | original (from `samples/` or `quarantine/`) | sanitized copy, one-time download token | `remediation_status` completed / partial; dataset `remediated` / `partial_remediated` | `DOWNLOAD_TOKEN_EXPIRY_MINUTES` | Sanitizer error → 500 | `test_sanitizer.py` (24), `test_remediation.py` (5) |
| 21 | Verification re-scan | `run_scan(sanitized)` inside remediation (`remediation.py:120`) | sanitized file | rescan result used only for counts | completed if 0 findings above low/info | none | Local stages only: no VirusTotal, URLhaus, AbuseIPDB; result not stored as a scan report; ClamAV-unavailable or parse-incomplete rescans still count as completed (gap #5) | `test_eicar_audit::test_eicar_remediation_and_rescan`, `test_e2e_*` |
| 22 | Download | `GET /{id}/download-sanitized` | Bearer token | file | 403 used / invalid / expired | `DOWNLOAD_TOKEN_EXPIRY_MINUTES` | n/a | `test_remediation::test_download_sanitized_endpoint_and_path_traversal` |
| 23 | History | `GET /api/v1/history` | page | latest verdict per dataset | n/a | n/a | n/a | `test_history.py` (6) |
| 24 | Health | `GET /health`, `GET /health/diagnostics` | none | AV available / version, AI configured, Turnstile | n/a | n/a | No detector-level fields for YARA, heuristics or TI | `test_smoke.py` |

### Verdict rules (`engine.py:135-202`), in order
1. Parser error and no findings and ClamAV not infected → `scan_incomplete`, risk 0.
2. ClamAV infected → `malicious`.
3. Any critical finding (EICAR MAL-001, HEUR-004/005, critical YARA, FORM-002, SCRP-001, MAL-005/006) → `malicious`.
4. Any high or medium finding outside `malware_reference`, or heuristic risk ≥ 0.4 → `suspicious`.
5. Only `malware_reference` findings → `clean_with_limitations` + `MALWARE_REFERENCE_ONLY`.
6. Any limitation (ClamAV unavailable, partial coverage, parser limitation) → `clean_with_limitations`.
7. Otherwise `clean_verified`.

Threat intelligence and AI run after this and never change the verdict.

## 2. Detector and provider inventory

"Live-validated" means exercised against the real service during Phase A. Phase A had no Docker and no network egress, so nothing external was live-validated.

| Component | Present | Wired into scan | Enabled by default | Tested | Live-validated in Phase A | Evidence |
|---|---|---|---|---|---|---|
| SHA-256 identity | yes | yes (upload and scan) | yes | yes | yes (local run) | `file_service.py:185`, `engine.py:215` |
| ClamAV (clamav-rest) | yes | yes | yes, but needs the clamav-rest container | yes, mocked HTTP | no: daemon unreachable, every scan returned `clamav_status=skipped` + `CLAMAV_UNAVAILABLE` | `clamav.py`, Phase A run |
| MetaDefender Cloud | yes | yes when `AV_PROVIDER=metadefender` | no | no tests found | no | `metadefender.py:54` uploads the whole file |
| YARA (real yara-python, 4 rules) | yes | yes | yes (`ENABLE_YARA` ignored) | yes | yes: `YARA-002` fired on EICAR | `yara_scanner.py`, Phase A run |
| "YARA-style" regex heuristics (HEUR-001..008) | yes | yes | yes | yes (33) | partly: no heuristic fired on the 4 fixtures; HEUR-007 inactive locally (no libmagic DLL), PE-import check inactive everywhere (`pefile` not installed) | `heuristics.py:85-97` |
| Raw byte signatures (MAL-001 EICAR etc.) | yes | yes | yes | yes | yes: MAL-001 critical on EICAR | Phase A run |
| Formula injection (FORM-001..003) | yes | yes | yes | yes | yes: FORM-001, FORM-003 on the fixture | Phase A run |
| Script / SQL injection rules | yes | yes | yes | yes | not exercised by the Phase A set | `content_checker.py:69-90` |
| Encoding normalisation | yes | yes (always on) | yes (`ENABLE_ENCODING_NORMALIZATION` ignored) | yes (8) | not exercised | `content_checker.py:24` |
| VirusTotal v3 (hash only) | yes | yes | flag true, needs key | yes (9), mocked | no; provider-down path verified (`vt_provider_error`, `VT_UNAVAILABLE_PROVIDER_ERROR`) | Phase A run d |
| URLhaus (lookup only) | yes | yes | flag true, needs key | yes (13) | no; provider-down path verified | Phase A run d |
| AbuseIPDB | yes | yes | flag true, needs key | yes (12) | no; provider-down path verified | Phase A run d |
| TI fusion / CONFLICTED | yes | yes | yes | yes (9) | provider-down only (`status=error`, `PROVIDER_UNAVAILABLE`) | Phase A run d |
| AI gateway (Cloudflare AI Gateway) | yes | in groq / cloudflare / llm_service paths | no (`AI_GATEWAY_ENABLED=false`) | `verify_gateway.py` (script, not pytest) | no | `llm_service.py:667` |
| AI guardrails ALLOW / RESTRICT / BLOCK | yes | yes, before any LLM call | yes | yes + benchmark fixtures | only the ALLOW path with no provider (`AI_PROVIDER=none` → `status=unavailable`, `llm_invoked=false`) | Phase A run |
| Remediation (sanitizer) | yes | yes | yes | yes (24 + 5) | yes: EICAR and formula fixtures, both `completed`, download single-use (2nd download 403) | Phase A run b, c |
| Re-scan after remediation | yes | yes, local stages only | yes | yes | yes, with ClamAV unavailable during the rescan | Phase A run b, c |
| PhishTank, Shodan, HIBP, SecurityTrails | config flags only | no | no | no | no | `config.py:156-159` |
