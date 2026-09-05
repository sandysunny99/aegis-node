# Threat Intelligence Validation

## VirusTotal
- **Status**: **IMPLEMENTED** (5/5 tests passing)
- **Methodology**: Hash-first lookup. The complete dataset is never uploaded; only SHA-256 hashes of detected malware artifacts are queried.
- **Privacy**: Preserves confidentiality.
- **Configuration**: Disabled by default (`ENABLE_VIRUSTOTAL=false`).

## URLhaus
- **Status**: **SCAFFOLDED**
- **Methodology**: Adapter exists, but is not currently connected to the scanner path. IOC extraction (identifying URLs in dataset content) must be implemented before activating this provider.
- **Configuration**: Disabled by default (`ENABLE_URLHAUS=false`).

## AbuseIPDB
- **Status**: **SCAFFOLDED**
- **Methodology**: Adapter exists, but is not currently connected to the scanner path. IOC extraction (identifying IPs in dataset content) must be implemented before activating this provider.
- **Configuration**: Disabled by default (`ENABLE_ABUSEIPDB=false`).
