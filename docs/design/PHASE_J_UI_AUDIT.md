# Phase J: Bastion UI against the real backend (17 Oct 2026)

Branch `feat/bastion-frontend` only. No backend scanner changes and no merge from the detection branches. The backend reference is the merged `core-baseline-v2` (9f473b0).

## Audit: where every displayed value comes from

| Screen | Value | Source | Finding |
|---|---|---|---|
| Overview | dataset count, per-status counts | `GET /history?ids=` items, `statusToPlate` | Real data |
| Overview | recent scans | history `scanned_at`, `threats_found_count` | Real data |
| Datasets | size, format, last scan, findings, ID | history items | Real data. No source or row-count column: the API has neither |
| Detail | verdict, coverage, rows, risk, AV, detector gaps | `GET /{id}/report` | Real data. Coverage now says "Partial … content beyond that was not checked" when `coverage_status` is not FULL |
| Detail / scan | threat-intel provider states | `threat_intel.status`, `providers_checked`, `evidence[]` | **Fixed.** Previously a single list. Now each of VirusTotal, URLhaus and AbuseIPDB is shown as match, no match, unavailable, not queried or not configured (`status/layers.js`, 8 unit tests) |
| Detail / scan | AI state | `GET /{id}/analysis` (404 = not run) | **Fixed.** It is now shown as a separate layer: not run, blocked by guardrail, completed, unavailable or failed |
| Settings | AV, AI, Turnstile, limits, version | `GET /health` | Real data |
| Landing | shield plates | `landing.fixtures.js` | Labelled on the page as an illustration with sample datasets |

## Failed requests never show as empty

| Place | Before | After |
|---|---|---|
| Ctrl/⌘K search | Said "No datasets uploaded" when the dataset request had failed | Says the datasets could not be loaded |
| AI provider list | A failed `/llm/providers` request silently disabled manual mode | A visible note explains it |
| Scan page | An unreachable API left the upload button live with no warning | An error banner says the API is not answering |
| Overview, datasets, detail, settings, AI | Already had error and retry states | Unchanged |

## Result layers

The new `components/ResultLayers.jsx` card ("What was checked") shows three separate columns on the scan report and the dataset page:
1. **Local scan.** It decides the verdict and shows the verdict, coverage, antivirus state and any detectors not run.
2. **Threat intelligence.** Extra evidence only: the overall state plus each provider's state.
3. **AI analysis.** Advisory only.

This keeps the following visibly different: a malicious finding, a clean local scan with partial enrichment, an incomplete scan, and an unverified remediation.

## Known backend semantics the UI reports as-is

- URLhaus `not_found` arrives as `reputation: "benign"` (`enrichment._url_evidence`). The UI labels any `benign` as "No malicious match… not proof the data is safe". The mapping itself belongs to the detection thread (master brief B3).
- **Forward-compatible (18 Oct):** the detection branch `integrate/core-audit` (not merged here) adds `evidence[].result_state`, `enrichment_status` and `INSPECTION_LIMIT:<limit>=<n>` limitation codes. `layers.js` prefers `result_state` and `enrichment_status` when present and falls back to `error_status` / `reputation` / `status` for older reports, so a NO_MATCH with reputation `unknown` still reads as a no-match and NOT_QUERIED lookups never count as checks. `limitations.js` describes the inspection-limit codes. Covered by 3 new unit tests.
- The API has no stale or cache-age field, so the UI shows no "stale" state. It will once the provider contract adds one.

## History page (18 Oct)

Built against the scan history API contract on `integrate/core-audit` (4d8072d, `docs/SCAN_HISTORY_API.md` there). Nothing is merged; the backend on this branch does not have the routes yet.

| Screen | Value | Source |
|---|---|---|
| History (`#/app/history`) | scans newest first, verdict, current dataset status, threat-intel state, coverage, findings | `GET /api/v1/scans?ids=` with the verdict / dataset status / format / threat-intel / target / date filters and paging |
| Scan (`#/app/history/<scan_id>`) | what ran, step by step; evidence; details; "Not recorded" for null `started_at`, `av_provider`, `profile` | `GET /scans/{id}`, `GET /scans/{id}/events` |
| Dataset page, "Scan history" | every scan of the dataset (incl. verification re-scans) and its full timeline | `GET /datasets/{id}/scans`, `GET /datasets/{id}/events` |
| All three | warning that history is lost on restart | `persistence.durable: false` |

States checked in a browser against both a backend without the routes (this branch) and one with them (`integrate/core-audit`), each run locally with no API keys, providers off and a synthetic 3-row CSV:
- **Routes present:** the list, the scan timeline (ClamAV shown as unavailable, threat intelligence off) and the dataset timeline all render real data.
- **Routes absent:** each place says the server has no scan history; the dataset page falls back to its latest-scan summary.
- **Backend down:** "Scan history could not be loaded" with Retry, never an empty list.

The non-durable warning is covered by unit tests (`status/history.test.mjs`, 5 tests); both local databases reported themselves durable.
