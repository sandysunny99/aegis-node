# Phase 9.2 - URLhaus Threat Intelligence

## Purpose
URLhaus is a community-driven database of malware-distribution URLs. This integration enables Aegis Node to enrich extracted URLs found within untrusted dataset contents by querying the URLhaus API. URLhaus acts strictly as **external threat intelligence** and does NOT replace the local detection heuristics (ClamAV/YARA/rules).

## Integration Architecture
Dataset → safe URL extraction → URLhaus lookup → normalized ThreatIntelResult → evidence fusion

1. **Extraction**: Aegis extracts HTTP/HTTPS URLs locally by scanning the dataset's raw bytes directly using a safe RegEx pattern without evaluating or resolving the links.
2. **Lookup**: Aegis issues a `POST` request to `https://urlhaus-api.abuse.ch/v1/url/` with the extracted URL inside the `data` payload.
3. **Normalization**: The URLhaus payload translates into our generic `ThreatIntelResult` schema matching Phase 9.1 semantics.
4. **Fusion**: URLs flagged as malicious do not overwrite a local "clean_verified" result but are appended to `result.content_findings` under the `urlhaus_{status}` rule ID, with `CONFLICT_URLHAUS_MALICIOUS` securely tracking the disagreement.

## SSRF Security Boundary
**Extracted URLs are NEVER fetched by Aegis.**
A critical security rule enforced through extensive testing (`test_ssrf_boundary_attacker_url`) proves that an attacker-controlled URL can never coerce the backend into issuing an HTTP request to the target itself (e.g., hitting internal metadata servers `169.254.169.254`). All network calls route exclusively and strictly to the official `urlhaus-api.abuse.ch`.

## Privacy Model (IOC-Only)
Unlike VirusTotal (which requires SHA-256 hashes of the files), the URLhaus lookup strictly requires only the extracted **URL** as the IOC.
- No files are uploaded.
- No CSV rows, tokens, local detection results, or filenames are transmitted to URLhaus.

## API Authentication & Status
- The official URLhaus Community API (`/v1/url/`) is free under fair-use principles.
- Authentication utilizes the `URLHAUS_AUTH_KEY` configured via backend environment parameters securely.
- No keys are exposed to the frontend or committed.
- No dataset is bulk-submitted. We query explicitly and only what we extract.

## Failure Semantics
Failure paths are heavily isolated to prevent local scanner degradation:
- `NOT_FOUND` (404/no_results) does not equal `CLEAN`.
- `PROVIDER_ERROR`, `TIMEOUT`, `RATE_LIMITED`, `UNAUTHORIZED`, `FORBIDDEN` degrade gracefully to `low` severity informational findings.
- The local security pipeline always functions effectively if URLhaus is completely offline.

## Cache Behavior
We integrated an efficient, isolated Dictionary Cache specifically keyed to `urlhaus:{normalized_url}` with a 1-hour TTL and bounded LRU/Eviction limit (1000 items) exactly mirroring Phase 9.1 constraints.

## Testing & Regression
`tests/test_urlhaus.py` covers 100% of the stated requirements, utilizing `MagicMock` over `httpx.AsyncClient` to securely test authentication drops, cache isolation, timeouts, 5xx errors, HTTP rate limits, and the SSRF safety boundary without relying on live connectivity. 
The database configuration remains completely un-migrated as intelligence is appended natively inside the existing JSON finding schemas.
