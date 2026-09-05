# API Privacy Matrix

| API Integration | Data Intended (Sent) | Data explicitly NOT sent | Privacy Guarantee |
|---|---|---|---|
| **VirusTotal** | SHA-256 Hash | File bytes, raw dataset contents, PII, CSV rows | File contents never leave the server; only mathematical hashes are sent. |
| **URLhaus** | Extracted URLs | Private IPs, internal hostnames, credentials | URLs checked against localhost/private subnets before submission. |
| **AbuseIPDB** | Extracted Public IPs | Private IPs, subnets (10.0.0.0/8, etc.), MACs | Read-only IP lookup. IP validation blocks private addresses. |
| **PhishTank** | Extracted URLs | Non-URL text, credentials | Only well-formed external URLs are checked. |

## Privacy Tests
A suite of tests must guarantee that:
1. 	est_virustotal_privacy.py mocks httpx.get and asserts the payload only contains hashes.
2. 	est_url_extraction.py asserts private/internal URLs are discarded before external lookup.
