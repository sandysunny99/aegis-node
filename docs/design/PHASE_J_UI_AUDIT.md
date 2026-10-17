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
- The API has no stale or cache-age field, so the UI shows no "stale" state. It will once the provider contract adds one.

## Waiting on another thread

- **History page:** this is held until the coordinator relays the history API contract from the detection thread. No History route or nav item exists until that API works.
