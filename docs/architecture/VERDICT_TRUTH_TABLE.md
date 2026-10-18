# Verdict, status and enrichment truth table

One table for what the scanner decided, what is stored, and what the UI should say. Source of truth: `scanner/engine.py: _determine_verdict`, `backend/routers/datasets.py: dataset_status_for_verdict`, `backend/routers/remediation.py: remediation_outcome`, `backend/services/threat_intelligence/`. Updated 18 Oct 2026.

## 1. Local verdict (decided before any threat intel runs, never changed by it)

Checked in this order; the first match wins.

| # | Condition | Verdict | Stored dataset status | UI label |
|---|---|---|---|---|
| 1 | Parser failed, no findings, ClamAV not infected | `scan_incomplete` | `incomplete` | Scan incomplete |
| 2 | ClamAV infected | `malicious` | `quarantined` (file moved) | Malicious |
| 3 | Any critical finding (EICAR MAL-001, validated PE in HEUR-005, critical YARA, FORM-002, SCRP-001, MAL-005/006) | `malicious` | `quarantined` | Malicious |
| 4 | Any high/medium finding outside `malware_reference`, or heuristic risk ≥ 0.4 | `suspicious` | `suspicious` | Suspicious |
| 5 | Only `malware_reference` findings | `clean_with_limitations` + `MALWARE_REFERENCE_ONLY` | `clean_limited` | Clean, with limitations |
| 6 | Any limitation: `CLAMAV_UNAVAILABLE`, `PARTIAL_DATASET_SCAN`, `INSPECTION_LIMIT:*`, `PARSER_LIMITATION`, `DETECTOR_UNAVAILABLE:*`, `DETECTOR_DISABLED:*` | `clean_with_limitations` | `clean_limited` | Clean, with limitations |
| 7 | None of the above | `clean_verified` | `clean` | Clean (verified) |

Consequences:
- No working AV result → rule 6 → never `clean_verified`.
- Partial coverage (row cap, XLSX row cap, CSV over the cap) → rule 6 → never `clean_verified`; `coverage_status` is `PARTIAL`.
- Low findings (e.g. `possible_executable_marker`, VT-era `low`) never change the verdict.
- Unknown verdict strings map to `incomplete`.
- Legacy rows written before 15 Oct 2026 may say `clean` for limited scans; the stored report `verdict` is authoritative.

## 2. Threat-intel enrichment (separate field `enrichment_status`)

| Situation | `enrichment_status` | Effect on verdict |
|---|---|---|
| No provider enabled with a key | `DISABLED` | none |
| Every lookup answered (MATCH or NO_MATCH) | `COMPLETE` | none |
| Some lookups failed | `PARTIAL` | none; failures listed as `<PROVIDER>_UNAVAILABLE_<STATE>` |
| Every lookup failed | `UNAVAILABLE` | none |
| A provider says malicious while the local verdict is clean | — | `CONFLICT_TI_MALICIOUS` / `CONFLICT_VT_MALICIOUS` limitation added; verdict unchanged |

Policy (owner decision, 17 Oct 2026): an optional threat-intel outage does not block the local verdict; it is shown as its own status. `clean_verified` never means every optional database answered.

Per-lookup `result_state`: `MATCH`, `NO_MATCH`, `TIMEOUT`, `RATE_LIMITED`, `UNAUTHORIZED`, `UNAVAILABLE`, `INVALID_RESPONSE`, `NOT_QUERIED`. `NO_MATCH` is never "safe": URLhaus `not_found` maps to reputation `unknown` (changed 18 Oct 2026; it was `benign`). A no-match or an outage can never cancel a local malicious finding (tested).

## 3. Remediation

| Re-scan of the sanitized copy | `remediation_status` | Dataset status |
|---|---|---|
| Findings above low remain | `partial` | `partial_remediated` |
| No findings above low, and re-scan `clean_verified`, coverage FULL, ClamAV available, no `CLAMAV_UNAVAILABLE` / `PARSER_LIMITATION` / `DETECTOR_UNAVAILABLE` | `completed` | `remediated` |
| No findings above low, but the re-scan could not prove it | `unverified` | `remediated_unverified` |

Re-scanning the original of any remediated dataset returns 409 and keeps its status.

## 4. Where each value is consumed

| Value | Persisted in | Read by |
|---|---|---|
| verdict, limitations, coverage | `scan_reports` | `/scan`, `/report`, `/history`, AI analysis |
| dataset status | `datasets.status` | `/datasets/{id}`, `/history` |
| enrichment_status, evidence, result_state | `scan_reports.threat_intel_json` | `/scan`, `/report` |
| remediation status, rescan verdict | `remediations`, `scan_reports` (`scan_target=sanitized`) | `/remediate`, `/remediation` |
| Bastion UI | `feat/bastion-frontend` maps these in its status map | owned by the UI thread |
