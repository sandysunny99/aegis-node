# Phase 9: Threat Intelligence Enrichment Plan
**Focus:** VirusTotal Hash-First Reputation

## 1. API Integration Strategy
- **Endpoint:** `GET https://www.virustotal.com/api/v3/files/{id}` (where `{id}` is the SHA-256 hash).
- **Authentication:** `x-apikey` header containing the VirusTotal Public API Key.
- **Rate Limits (Public API):** 4 requests/minute, 500 requests/day. Strict compliance required to avoid HTTP 429.
- **Privacy Implications:** Submitting a SHA-256 hash simply asks VT if it has seen the file before. It does **not** upload the user's dataset contents, perfectly preserving the privacy required for untrusted/sensitive files.

## 2. Aegis Normalized Representation
The system will normalize the VT response into a standard `ThreatIntelResult` schema to ensure independence from any single provider.

**Provenance Fields:**
- `provider`: "virustotal"
- `indicator_type`: "file_hash"
- `indicator`: The SHA-256 string
- `verdict`: `malicious`, `suspicious`, `clean`, `unknown`, or `error`
- `confidence`: String ratio (e.g., "14/72" engines detected)
- `lookup_timestamp`: ISO-8601 UTC timestamp
- `error_status`: e.g., "rate_limited", "not_found", "timeout"
- `raw_reference_id`: VT analysis link or ID

## 3. Conflict Handling
If VT returns `clean` but local ClamAV/YARA returns `malicious` (or vice versa), Aegis will **preserve the disagreement**. 
The final evidence aggregator will escalate conflicting verdicts as `suspicious` or flag them for the LLM interpretation phase. External intelligence remains **enrichment**, not the final security authority.

## 4. Timeout & Failure Behavior
- **Timeout:** Configurable timeout (e.g., 5 seconds) for the external API call.
- **Graceful Degradation:** If VT timeouts, returns HTTP 429 (Rate Limit), or HTTP 500+, the pipeline logs the error and continues with local scanning results. It must **never** fail the scan operation simply because an external TI provider is unavailable.

## 5. Caching Strategy
Given the strict 4 req/min rate limit, caching is required.
Since complex infrastructure (Redis/Memcached) is prohibited for this M.Tech scope:
- Use an in-memory TTL cache (e.g., `cachetools.TTLCache` or similar) for immediate repetitive uploads.
- Alternatively, persist the TI results natively in the SQLite `DatasetRecord` so subsequent AI analysis calls can retrieve it without hitting VT again.

## 6. Security Risks
- **SSRF:** Validating that the hash is strictly a 64-character hex string prevents injection into the VT endpoint URL.
- **Data Leakage:** No file payloads are sent.

## 7. Tests Required
- `test_vt_hash_malicious`: Mocks a 200 OK with >0 malicious engines.
- `test_vt_hash_clean`: Mocks a 200 OK with 0 malicious engines.
- `test_vt_hash_not_found`: Mocks a 404 (hash unseen).
- `test_vt_rate_limited`: Mocks a 429 (ensures pipeline doesn't crash).
- `test_vt_timeout`: Mocks an HTTP timeout (ensures pipeline degradation).
- `test_invalid_hash_format`: Ensures strictly formatted hashes are submitted.

## 8. Files Expected to Change
- `backend/config.py`: Add `VT_API_KEY` and rate-limit settings.
- `backend/schemas.py`: Define `ThreatIntelResult` and `ThreatIntelProvider`.
- `backend/models.py`: Map the TI results back to `DatasetRecord` or a new `ThreatIntelRecord`.
- `backend/services/threat_intelligence/virustotal.py`: Implement the hash lookup adapter.
- `backend/routers/datasets.py`: Integrate the optional lookup after local scanning.
- `tests/test_virustotal.py`: Unit tests for the VT adapter.
