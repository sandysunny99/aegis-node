# Aegis Node: Threat Intelligence

## Overview
Aegis Node enriches local deterministic scans with external Threat Intelligence (TI). 

## URLhaus Integration
- **Lookup-Only:** Hashes and domains are queried via API.
- **No URL Fetching:** The system will NEVER connect to a discovered malicious URL.
- **Bounded Lookup:** Prevents Server-Side Request Forgery (SSRF) and active probing.

## AbuseIPDB Integration
- **Lookup-Only:** IP addresses are queried for reputation.
- **Public-IP Filtering:** Internal/private IPs (RFC 1918) are excluded from lookups to prevent leakage or SSRF.
- **Bounded Lookup:** Passive querying only.

## TI Fusion Engine
- **Normalized Evidence:** Raw provider data is mapped to a standard Aegis format.
- **Corroboration:** Multiple providers indicating malicious intent increase evidence strength (`CORROBORATED`).
- **Conflict:** Disagreements between local scans and TI providers yield a `CONFLICTED` state for analyst review.
- **Provider Failure:** TI is non-blocking. If URLhaus or AbuseIPDB are unavailable, the local deterministic verdict remains authoritative.
