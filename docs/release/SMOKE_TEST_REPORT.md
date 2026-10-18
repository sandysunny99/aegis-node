# Smoke test report

## Local, release candidate (18 Oct 2026)

Environment: Docker Desktop 29.8.2 on Windows 11; `docker-compose.yml` of the release branch with a test override (own container names, port 127.0.0.1:8020, `AI_PROVIDER=none`); hardened app container (read-only root, `cap_drop: ALL`, `pids_limit 256` — confirmed with `docker inspect`); real ClamAV 1.5.4 (signatures 28136, 27 Sep 2026, bundled database before freshclam ran). Image built from `b2ae2c3`, rebuilt from `2045b7f` for the last two checks. Test stack and its volumes removed afterwards.

| # | Check | Result |
|---|---|---|
| 1 | Harmless CSV via API | 201 / 200, `clean_verified`, ClamAV clean, coverage FULL 4/4, status `clean` |
| 2 | EICAR whole file | `malicious`, ClamAV `Eicar-Test-Signature`, quarantined, remediation `completed` with `clean_verified` re-scan, re-scan of original 409 |
| 3 | EICAR inside a CSV row | `malicious` via YARA-002 + MAL-001 (ClamAV does not match EICAR mid-file) |
| 4 | Formula-injection fixture | `suspicious` (FORM-001, FORM-003), remediated |
| 5 | Malformed JSON | `scan_incomplete`, status `incomplete`, PARSER_LIMITATION |
| 6 | 51 MB upload | 413 |
| 7 | ClamAV REST stopped (rebuild `2045b7f`) | clean CSV → `clean_with_limitations` + CLAMAV_UNAVAILABLE; EICAR CSV still `malicious` |
| 8 | Timestamps (rebuild `2045b7f`) | `/api/v1/scans` `completed_at` ends with `Z`; `persistence.durable: true` on the Docker volume |
| 9 | Browser, built-in pane | Landing, History (5 scans, filters, pagination, "Dataset now" column), dataset detail with "What was checked", findings, scan history (original + verification re-scan), timeline (upload → detectors → scan → remediation → re-scan) all rendered from real API responses |
| 10 | 390 px width | `scrollWidth == innerWidth` on `/`, `/app`, `/app/history`, dataset detail, `/app/scan`, `/app/settings` |
| 11 | Console | one error: `GET /datasets/{id}/analysis` 404 when no analysis exists (expected; UI shows "No AI analysis has been run") |

Not run: Lighthouse (not run at all), keyboard-only walkthrough, light theme visual check, AI analysis with a real provider, live MalwareBazaar/ThreatFox, anything on Render or Oracle.

## Preview / production

Not deployed yet.
