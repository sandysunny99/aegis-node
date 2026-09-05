# Threat Intelligence (CTI) APIs Evaluation for Aegis Node

**Document Type**: Cyber Threat Intelligence (CTI) Research & Feasibility Study  
**Version**: 1.0.0  
**Target Capabilities**: Hash Reputation, C2 IP Lookup, Malicious URL Enrichment  

---

## 1. Candidate Threat Intelligence Providers

| Provider / API | Primary Capability | Free Tier Quota | Auth Method | Privacy & Data Leakage Risk | Accuracy & Coverage | M.Tech Integration Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **VirusTotal (v3)** | File Hash SHA-256 Reputation (70+ Antivirus Engines) | 4 req/min, 500 req/day | API Key (`x-apikey` header) | **Zero risk with Hash-First Lookup** (Do NOT upload full files) | **Highest** (Global industry standard) | **ADOPT (Optional Hash Lookup)** |
| **AbuseIPDB (v2)** | IP Address Reputation (C2, Brute-force, Scanners) | 1,000 checks/day | API Key (`Key` header) | Low (Queries only extracted IP strings) | High for network threat datasets | **ADAPT / DEFER (Secondary)** |
| **URLhaus (abuse.ch)** | Malicious URLs & Malware Distribution Endpoints | Unlimited / Free Public API | None / Open REST | Low (Queries domain/URL string) | High for web/phishing datasets | **REFERENCE ONLY** |
| **AlienVault OTX** | Indicator of Compromise (IoC) Pulse Feeds | 10,000 req/day | API Key | Low | Moderate (Community pulses) | **DEFER** |

---

## 2. Threat Intelligence Integration Architecture

The integration follows a strict **Defense-in-Depth, Privacy-First Architecture**:

```
                       DATASET INGESTION
                               │
                               ▼
                       SHA-256 Checksum
                               │
                               ▼
                   ┌───────────────────────┐
                   │  Local Scanning Core  │
                   │ (ClamAV, YARA, Rules) │
                   └───────────┬───────────┘
                               │
                               ▼
                   Is VIRUSTOTAL_API_KEY set?
                     │                   │
                    YES                  NO
                     │                   │
                     ▼                   ▼
           ┌──────────────────┐  [Skip External CTI]
           │ Query VirusTotal │  (Zero network latency)
           │ via SHA-256 Hash │
           └─────────┬────────┘
                     │
                     ▼
           ┌──────────────────────────────────────┐
           │     Evidence Aggregator & Scoring     │
           │  Local Evidence + External Reputation │
           └──────────────────────────────────────┘
```

---

## 3. Privacy & Guardrail Principles

1. **Hash-First Invariant**: Aegis Node calculates the SHA-256 checksum locally during streaming upload and only queries the hash. The dataset body, cells, and file content are **never uploaded to external servers**.
2. **Graceful Degradation (Fail-Open/Fail-Safe)**:
   - If `VIRUSTOTAL_API_KEY` is not set $\rightarrow$ External reputation status is `UNCONFIGURED` and the local scan proceeds at full speed.
   - If the API returns HTTP 429 (Rate Limit) or HTTP 404 (Hash Not Found) $\rightarrow$ Status is `NOT_FOUND_OR_RATE_LIMITED`.
   - An external API failure **NEVER** turns a malicious file into `CLEAN` and **NEVER** crashes the scan.
3. **No Blind Trust**: External reputation is treated as an advisory evidence signal (`external_reputation_signal`). The authoritative verdict is calculated by Aegis Node's multi-engine policy.
