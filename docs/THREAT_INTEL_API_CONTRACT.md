# Threat-intel evidence contract

Every external lookup becomes one `NormalizedTIEvidence` item inside `threat_intel.evidence` of a scan. External evidence never changes the local `verdict` (see `docs/architecture/VERDICT_TRUTH_TABLE.md`). Updated 18 Oct 2026.

## Evidence item

| Field | Meaning |
|---|---|
| `provider` | `virustotal`, `urlhaus`, `abuseipdb`, `malwarebazaar`, `threatfox`, `circl_hashlookup` |
| `indicator_type` / `indicator` | `sha256` (file hash), `url`, `ipv4` |
| `result_state` | `MATCH`, `NO_MATCH`, `TIMEOUT`, `RATE_LIMITED`, `UNAUTHORIZED`, `UNAVAILABLE`, `INVALID_RESPONSE`, `NOT_QUERIED` |
| `reputation` | `malicious`, `suspicious`, `benign` (VirusTotal 0 detections, AbuseIPDB score 0), `known_good` (CIRCL), `unknown` (no match or failure) |
| `error_status` | lower-case failure state, or null when the provider answered |
| `category`, `confidence`, `reference_url` | provider facts when present (malware family, `trust:100`, report link) |

`NO_MATCH` is never "safe"; a failure is never a no-match; `known_good` is ignored by fusion and cannot lower a local finding.

## What each provider receives

| Provider | Sends | Endpoint (fixed) | Flag | Key |
|---|---|---|---|---|
| VirusTotal | file SHA-256 | `www.virustotal.com/api/v3/files/{sha256}` | `ENABLE_VIRUSTOTAL` | `VIRUSTOTAL_API_KEY` |
| URLhaus | up to 5 extracted URLs | `urlhaus-api.abuse.ch/v1/url/` | `ENABLE_URLHAUS` | `URLHAUS_AUTH_KEY` |
| AbuseIPDB | up to 5 public IPv4 | `api.abuseipdb.com/api/v2/check` | `ENABLE_ABUSEIPDB` | `ABUSEIPDB_API_KEY` |
| MalwareBazaar | file SHA-256 (`get_info`) | `mb-api.abuse.ch/api/v1/` | `ENABLE_MALWAREBAZAAR` | `ABUSECH_AUTH_KEY` |
| ThreatFox | file SHA-256 (`search_hash`), up to 5 URLs (`search_ioc`, exact match) | `threatfox-api.abuse.ch/api/v1/` | `ENABLE_THREATFOX` | `ABUSECH_AUTH_KEY` |
| CIRCL hashlookup | file SHA-256 | `hashlookup.circl.lu/lookup/sha256/{sha256}` | `ENABLE_CIRCL_HASHLOOKUP` | none |

No provider receives file contents, rows or filenames; no adapter downloads samples, submits files or reports indicators. Even a hash, URL or IP query tells that provider the indicator exists.

## Safeguards in the new adapters (`services/threat_intelligence/lookups.py`)

Per-request timeout (`THREAT_INTEL_TIMEOUT_SECONDS`, default 8 s, 5 s connect); responses over 1 MB, non-JSON or of the wrong shape → `INVALID_RESPONSE`; redirects not followed; answers cached for 1 hour by (provider, type, indicator), failures not cached; concurrent lookups of the same indicator share one request; single attempt, no retry storm. Per scan the most requests are 1 per hash provider plus 5 URL lookups for ThreatFox.

Tested in `tests/test_new_ti_providers.py`: match, no match, disabled, missing key, 401, 403, 429, 503, timeout, connection error, not JSON, wrong root type, wrong `data` type, oversized, cache hit, failures not cached, invalid hash never sent, known-good with a malicious local finding, external match on a clean scan (conflict, verdict unchanged), partial enrichment. No live calls were made.
