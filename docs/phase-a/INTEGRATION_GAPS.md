# Aegis Node integration gaps (Phase A)

Found at `c895a6b` by reading the code and by a local end-to-end run (uvicorn, ClamAV unreachable, all outbound HTTP pointed at a dead local proxy). "Observed" means the Phase A run reproduced it. "Audit branch" says whether `fix/audit-2026-10` already changes that code; that branch does not contain `c895a6b`.

Severity: **High** = the product shows or stores "clean / safe / no evidence" when that is not what the backend proved. **Medium** = wrong state, lost evidence or a privacy default. **Low** = cosmetic, dead code or hygiene.

## Defects in the frozen core (need a decision before any fix)

| # | Severity | Gap | Evidence | Audit branch |
|---|---|---|---|---|
| 1 | High | `scan_incomplete` and `clean_with_limitations` are stored as dataset status `clean`. Only `malicious` and `suspicious` get their own status. | `backend/routers/datasets.py:329-336`. Observed: malformed JSON → verdict `scan_incomplete`, stored status `clean`; provider-down scan → stored `clean`. | Same code |
| 2 | Medium | Re-scan request on a remediated dataset sets status to `error` before returning 409, so a remediated dataset permanently shows `error`. | `datasets.py:155-163`. Observed: EICAR and formula datasets went `remediated` → `error`; history row shows `error`. | Fixed (C1, `d6e43e1`) |
| 3 | Medium | Remediation is marked `completed` from finding counts alone. The re-scan's own verdict and limitations are ignored (ClamAV unavailable, `scan_incomplete`, partial coverage), threat intel is not re-run, and the re-scan is not stored as a scan report. | `backend/routers/remediation.py:121-169`. Observed: EICAR remediation `completed` while ClamAV was unreachable. | Same logic |
| 4 | Medium | CSV `rows_total` counts every line, including a trailing blank line, so a fully scanned clean CSV is reported as `PARTIAL_DATASET_SCAN` (80 %) and can never reach `clean_verified`. Quoted multi-line cells inflate it the same way. | `scanner/content_checker.py:304`. Observed: `tests/fixtures/aegis_validation/clean/clean_dataset.csv` (4 rows + trailing blank line) → 4/5 rows, PARTIAL. | Same code |

Proposed minimal fixes (not applied; each starts with a failing test):

- **#1** Map `scan_incomplete` → new status `incomplete` and `clean_with_limitations` → `clean_limited` (or keep `clean` only for `clean_verified`). Test: scan the malformed fixture, assert stored status is not `clean`. This adds status values, which the prompt treats as a frozen-core change, so it needs your approval and a matching UI mapping.
- **#2** Take the audit branch's C1 change (check remediated state before the atomic `scanning` update). Test: remediate, re-scan, assert 409 and status still `remediated`.
- **#3** Mark remediation `partial` (or a new `unverified`) when the re-scan verdict is not `clean_verified` / `clean_with_limitations`, or when its limitations include `CLAMAV_UNAVAILABLE` or `PARSER_LIMITATION`; persist the re-scan as a `ScanReportRecord`. Test: remediate with ClamAV mocked unavailable, assert status is not `completed`.
- **#4** Count rows with the same CSV parser used for inspection (or ignore blank lines). Test: clean fixture with trailing newline → `coverage_status == "FULL"`.

## Backend ↔ UI gaps

| # | Severity | Gap | Evidence | Audit branch |
|---|---|---|---|---|
| 5 | High | The Threat Intelligence card reads fields the API never returns (`virustotal`, `urlhaus`, `abuseipdb`, `url_count`, `ip_count`, `malicious_found`). It always shows VirusTotal "0 malicious" in green, "No malicious match", "No malicious evidence" and "0 IOCs extracted", whatever the real evidence, including malicious hits and `status=error`. The API returns `status`, `evidence[]`, `evidence_strength`, `providers_checked`, `limitations`, `conflicts`. | `frontend/src/components/ThreatIntelligence.jsx:24-60` vs `backend/schemas.py: TIFusionReport` | Same code |
| 6 | High | `verification_limitations` is never rendered, nor `coverage_status`, `rows_total`, TI `evidence_strength`, `conflicts` or `limitations`. `CLAMAV_UNAVAILABLE`, `PARTIAL_DATASET_SCAN`, `CONFLICT_TI_MALICIOUS` and `CONFLICT_VT_MALICIOUS` are invisible to the user. | `grep` finds none of these names under `frontend/src` | Same code |
| 7 | High | Several UI paths turn "not proven" into "clean": `StatusBadge` falls back to "Clean (Verified)" for any unknown verdict; `FindingsList` says "No malicious findings detected" for an incomplete scan; `RemediationCard` says "Dataset is Clean. No threats were detected." whenever `threats_found_count` is 0 (true for `scan_incomplete` and provider-down scans); History colours every verdict other than malicious/suspicious green, including `scan_incomplete`. | `StatusBadge.jsx:11`, `FindingsList.jsx:6`, `RemediationCard.jsx:26,49`, `HistoryPage.jsx:50` | Same code |
| 8 | Medium | "YARA: Enabled" and "Heuristics: Active" are hard-coded (audit finding #5). `/health` has no detector fields to drive them. | `frontend/src/App.jsx:334-335`, `backend/main.py:97-153` | Same code |
| 9 | Medium | The VirusTotal result is stored as a finding (`vt_unconfigured`, `vt_not_found`, `vt_provider_error`...) instead of in `threat_intel`, so every scan lists a VirusTotal row under "LOCAL DETECTION (Primary Authority)". It is not counted in `threats_found_count`. A 401/403 adds no limitation, so a bad key is silent. | `datasets.py:178-201`. Observed: `vt_unconfigured` (low) on every run-1 scan | Not checked |
| 10 | Medium | AI card: `api.js` rewrites 404 to "Resource not found...", so `AiSummary`'s `includes('404')` check never matches and a freshly scanned dataset shows "Error: Resource not found. Please refresh and try again." "LLM State" is derived from the guardrail, not `llm_invoked`, so it shows INVOKED when no model ran (observed `llm_invoked=false`). The AI verdict, severity, confidence, evidence, recommendations and limitations are never shown, and nothing labels the text "Advisory". | `api.js:19`, `AiSummary.jsx:34,140` | Not checked |
| 11 | Low | Stepper puts the user on "AI & Threat Insights" or "Remediation" from `threats_found_count` alone. | `App.jsx:205` | Same code |
| 12 | Low | Mock-mode banner claims "High-performance signature-less heuristic scanning ... running fully". | `App.jsx:224` | Same code |
| 13 | Low | Unused client functions (`getScanReport`, `getDatasetStatus`, `getRemediationReport`, deprecated `getSanitizedDownloadUrl` that puts the token in the URL) and an unused `RiskMeter`. A page reload loses the scan because the UI never re-fetches the report. | `frontend/src/api.js` | Not checked |

## Detector, provider and config gaps

| # | Severity | Gap | Evidence | Audit branch |
|---|---|---|---|---|
| 14 | Medium | Threat-intel flags default to **on**. `config.py` defines `enable_virustotal` and `enable_urlhaus` twice; the later `True` wins, so the "Default OFF for privacy" comment is wrong. `enable_abuseipdb` is `True`. Lookups run whenever a key is present. | `backend/config.py:147-152` and `177-184`; Phase A printed `vt True uh True ab True` with no `.env` | Fixed (`8e5bdde`, all three default `False`) |
| 15 | Medium | TI report says `status=active` with `providers_checked=["urlhaus","abuseipdb"]` even when neither provider is configured. | `datasets.py:212`. Observed in every run-1 scan | Changed (hard-coded list gone; not re-tested) |
| 16 | Medium | Detectors that fail to load add no limitation, so the scan can still be `clean_verified`: YARA import or compile failure returns `[]`; HEUR-007 MIME mismatch needs libmagic (missing in the local Windows venv); the PE-import heuristic needs `pefile`, which is not in `requirements.txt`, so it never runs anywhere. | `yara_scanner.py:43-64`, `heuristics.py:85-97`, `requirements.txt` | Not checked |
| 17 | Medium | `AV_PROVIDER=metadefender` uploads the whole file to MetaDefender Cloud. Off by default and untested, but it is the one path that sends user data to a third party, against hard boundary 3. | `backend/services/av_providers/metadefender.py:54` | Not checked |
| 18 | Low | Dead flags: `ENABLE_YARA` and `ENABLE_ENCODING_NORMALIZATION` are never read. `ENABLE_HEURISTICS` is read with `os.getenv`, so a value in `.env` is ignored when running outside Docker. | `grep` over `backend/` and `scanner/` | Not checked |
| 19 | Low | The AI layer receives findings, ClamAV status and risk score, but not the verdict, limitations or threat intel. | `routers/analysis.py:61-75` | Not checked |
| 20 | Low | URL and IP lookups take the first 5 items of a Python `set`, so which indicators are checked can differ between runs of the same file. | `datasets.py:232,273` | Changed (`d6e43e1` "bounded TI extraction"; not re-tested) |
| 21 | Low | EICAR yields two identical `MAL-001` findings (raw-byte and cell), so one string counts as 3 threats. `MAL-002` and `MAL-011` mean different things in the raw scan and in the rule table. | Observed run b; `content_checker.py:102-165,437-482` | Not checked |
| 22 | Low | CSV `mime_type` is stored as `application/vnd.ms-excel` on Windows (extension lookup through the registry) and reused as the download Content-Type. | Observed in every upload | Not checked |
| 23 | Low | `GET /api/v1/datasets/llm/providers` has no rate limit. | `routers/analysis.py:199` | Fixed (S7, `57be09a`) |
| 24 | Info | No frontend tests and no API contract tests for the fields the UI reads, which is how #5 went unnoticed. | `frontend/` has no test runner | Not checked |
