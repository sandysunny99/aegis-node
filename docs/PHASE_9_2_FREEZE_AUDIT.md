# Phase 9.2 Freeze Audit Report

## Implementation Summary
Phase 9.2 successfully integrated URLhaus as an external threat-intelligence source. 
The integration strictly implements lookup-only URL intelligence by extracting HTTP/HTTPS links from raw dataset bytes via regular expressions and deduplicating them into a bounded set. These URLs are transmitted directly to the URLhaus Community API, normalizing responses into the uniform `ThreatIntelResult` schema, and fused into `ContentFinding` objects appended to the overall scan report.

## Security Boundary
The core security properties enforce that:
1. URLhaus operates strictly as an enrichment/evidence layer.
2. The local scanner (ClamAV, YARA, heuristic rules) remains the primary authority.
3. Any intelligence returned by URLhaus never silences or overrides a local malicious or suspicious verdict.

## SSRF Boundary
**CRITICAL**: Extracted URLs from untrusted datasets are strictly treated as IOC strings and are **NEVER** fetched, evaluated, or requested by the backend directly.
This provides absolute protection against Server-Side Request Forgery (SSRF) whereby an attacker might submit `http://169.254.169.254` or `http://localhost`. The backend will only establish HTTP requests to `https://urlhaus-api.abuse.ch/v1/url/`, making local/private/link-local targets inherently unreachable by the extraction logic.

## Failure Semantics
URLhaus unavailable/unknown conditions fail safely:
- `not_found`, `invalid_url`, `timeout`, `provider_error`, `rate_limited`, `unauthorized`, `forbidden`, and `unconfigured` results are all strictly trapped and mapped to either a `low` severity finding or `not_found`.
- An unavailable URLhaus API does **NOT** equal `CLEAN`.
- A missing API key (`unconfigured`) allows local scanning to continue unimpeded.

## Evidence-Fusion Behavior
URLhaus evidence is appended to the report.
- A `malicious` URLhaus status creates a `critical` severity `ContentFinding`.
- If the local scanner reports `clean_verified` but URLhaus flags a URL as malicious, a `CONFLICT_URLHAUS_MALICIOUS` verification limitation is explicitly recorded to alert the analyst of the discrepancy without quietly changing the local findings context.

## Test Results
100% of the prescribed tests (286 total tests) continue to pass. The comprehensive test suite (`test_urlhaus.py`) verifies:
- Positive/Negative intelligence lookup
- Authentication absence handling
- Missing, Rate Limited, 5xx, and Unauthorized responses
- Cache isolation and TTL semantics
- Explicit SSRF boundaries (`test_ssrf_boundary_attacker_url`)

## Files Changed
- `backend/config.py`
- `backend/routers/datasets.py`
- `backend/services/threat_intelligence/urlhaus.py`
- `tests/test_urlhaus.py`
- `docs/PHASE_9_2_URLHAUS_REPORT.md`

## Research Impact
None. The A-F Ablation and the Benchmark test framework remain functionally frozen, untainted, and unchanged. The historical research foundation continues unaffected by real-time intelligence enhancements.

## Known Limitations
URLhaus lookup is strictly bound to maximum 5 URLs per file in order to respect API rate-limiting under fair-use guidelines and limit synchronous blocking time in the dataset scanning pipeline.
