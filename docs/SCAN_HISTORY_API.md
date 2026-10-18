# Scan history API contract

Status: implemented and tested on `integrate/core-audit` (`tests/test_scan_history.py`). Not deployed. All routes use the existing API-key guard and rate limits; ids are unguessable 32-character hex public ids.

## Routes

| Route | Purpose |
|---|---|
| `GET /api/v1/scans` | Paginated scans, newest first (`completed_at` desc, then internal id desc, so pages are stable) |
| `GET /api/v1/scans/{scan_id}` | One scan: summary fields + `risk_score`, `findings`, `threat_intel` |
| `GET /api/v1/scans/{scan_id}/events` | That scan's events, oldest first |
| `GET /api/v1/datasets/{dataset_id}/scans` | A dataset's scans, newest first, including verification re-scans (`target: "sanitized"`) |
| `GET /api/v1/datasets/{dataset_id}/events` | A dataset's whole timeline: upload, scans, AI analysis, remediation |

The existing `GET /api/v1/history` (one row per dataset, latest scan) is unchanged.

### `GET /api/v1/scans` query parameters

| Param | Values |
|---|---|
| `page`, `page_size` | `page ≥ 1`, `1 ≤ page_size ≤ 100` (default 20) |
| `ids` | Comma-separated dataset public ids. **Required in production when no API key is set** (403 otherwise), same rule as `/history` |
| `verdict` | `clean_verified`, `clean_with_limitations`, `suspicious`, `malicious`, `scan_incomplete` |
| `dataset_status` | `clean`, `clean_limited`, `incomplete`, `quarantined`, `suspicious`, `remediated`, `partial_remediated`, `remediated_unverified`, `error` |
| `file_format` | `csv`, `json`, `jsonl`, `parquet`, `xlsx`, `txt` |
| `enrichment_status` | `COMPLETE`, `PARTIAL`, `UNAVAILABLE`, `DISABLED` |
| `target` | `original` (default), `sanitized`, `all` |
| `since`, `until` | ISO 8601; `completed_at ≥ since`, `< until` |

There is no free-text search on the server; a search box can only filter the loaded page.

## Shapes

```jsonc
// ScanList (GET /scans, GET /datasets/{id}/scans)
{
  "total": 3, "page": 1, "page_size": 20,
  "items": [ScanSummary],
  "persistence": {"durable": false, "database": "sqlite",
                  "note": "SQLite on temporary storage: history is lost when the server restarts"}
}

// ScanSummary
{
  "scan_id": "9c1e…", "dataset_id": "4f2a…", "target": "original",
  "file_format": "csv", "file_size_bytes": 1234, "sha256": "…",
  "started_at": "2026-10-18T05:10:02Z",      // null for scans recorded before history existed
  "completed_at": "2026-10-18T05:10:03Z",
  "verdict": "clean_with_limitations",
  "dataset_status": "clean_limited",          // the dataset's CURRENT status
  "coverage_status": "FULL", "rows_inspected": 4, "rows_total": 4,
  "clamav_status": "skipped",                 // clean | infected | skipped
  "av_provider": "clamav_rest", "profile": "full",   // null on older rows
  "enrichment_status": "DISABLED",
  "threats_found_count": 0,
  "limitations": ["CLAMAV_UNAVAILABLE"]
}

// ScanDetail = ScanSummary + {"risk_score": 0.0, "findings": [...], "threat_intel": TIFusionReport|null}

// EventList
{"items": [ScanEvent], "persistence": {...}}

// ScanEvent
{"event_type": "DETECTOR_COMPLETED", "outcome": "ok",      // ok | failed
 "created_at": "…", "scan_id": "9c1e…" | null,
 "detail": {"detector": "clamav", "state": "unavailable", "clamav_status": "skipped"}}
```

`POST /datasets/{id}/scan` responses now also carry `scan_public_id` (use it for `/scans/{id}`) and `enrichment_status`.

## Event types and their `detail`

| Event | When | `detail` keys |
|---|---|---|
| `UPLOAD_ACCEPTED` | upload stored | `file_format`, `file_size_bytes`, `sha256` |
| `SCAN_STARTED` | status flipped to scanning | `profile`, `av_provider` |
| `DETECTOR_COMPLETED` | once per detector: `clamav`, `yara`, `heuristics`, `content_rules` | `detector`, `state` (`ran`, `unavailable`, `disabled`, `incomplete`), counts, `coverage_status`, rows |
| `THREAT_INTEL_LOOKUP_COMPLETED` / `_FAILED` | per configured provider that had indicators to look up | `provider`, `lookups`, `result_states` (e.g. `{"NO_MATCH": 2}`), `indicator_types` |
| `SCAN_COMPLETED` | report stored | `verdict`, `dataset_status`, `coverage_status`, `enrichment_status`, `limitations`, `duration_ms` |
| `SCAN_FAILED` | scan raised | `error` (exception class only), `dataset_status` |
| `AI_ANALYSIS_STARTED` / `_COMPLETED` | `/analyse` | `llm_mode`; then `status`, `llm_invoked`, `llm_bypassed`, `guardrail_status`, `guardrail_score`, `provider`, `fallback_used` (`outcome: failed` unless status is `completed`) |
| `REMEDIATION_STARTED` | `/remediate` began | `original_findings` |
| `VERIFICATION_SCAN_COMPLETED` | re-scan of the sanitized copy stored | `verdict`, `coverage_status`, `limitations`, `sanitized_sha256` |
| `REMEDIATION_COMPLETED` | remediation stored | `remediation_status` (`completed`, `partial`, `unverified`), `dataset_status`, `changes`, `remaining_actionable` |
| `REMEDIATION_FAILED` | sanitize or re-scan raised | `stage` |

Rules: no event for a step that did not run (no TI events when no provider is configured); failures are recorded as failures; details hold no file contents, original filenames, tokens or raw provider payloads (tested). Upload rejections create no event because no dataset exists. Events are append-only through the API (there is no update or delete route); this is not a cryptographic audit log.

## Persistence

`persistence.durable` is `true` only for SQLite on a mounted volume in the `full` profile (local Docker: `aegis_node_db` at `/app/db`), or an external database URL. Render free (`/tmp`) reports `false`; the UI should say history will not survive a restart. A PostgreSQL URL currently also needs a driver that is not installed (decision pending). Uploaded files are not needed to read history. Retention: no automatic deletion is implemented; history is kept until the database is removed.

## UI guidance (for the Bastion History page)

- Show `verdict` / `dataset_status`, `enrichment_status` and remediation states separately: a malicious finding, a clean local scan with `enrichment_status: PARTIAL`, an `incomplete` scan and a `remediated_unverified` dataset are four different things.
- A failed request is an error state with retry, never "No history".
- `started_at`, `av_provider` and `profile` can be null for old rows: show "Not recorded", not a guess.
