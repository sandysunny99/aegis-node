# Security Model
## Threat Boundaries
- **Untrusted Data**: Uploaded datasets are never executed. Parsed safely.
- **SSRF Prevention**: Extracted URLs are NOT fetched by the backend. They are only sent to reputation APIs (URLhaus/PhishTank).
- **Privacy Preservation**: Full files/rows are never sent to external APIs. Only hashes (SHA-256) or isolated public IOCs.
- **Graceful Degradation**: If external APIs fail or timeout, the system falls back to local detection without failing open.
