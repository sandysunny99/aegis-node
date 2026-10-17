# Threat-intelligence provider audit

Research date: **17 October 2026**. Sources are the providers' own pages; "not verified" means the official page could not be read or does not state the fact. No quota below is guessed.

Branch: `integrate/core-audit` at `9fd35e9` (tag `core-baseline-v2` = `9f473b0`, local only, nothing pushed).

## 0. Current state (Phase 0 audit)

### Architecture as built
Upload (Turnstile, API key, extension allow-list, streamed SHA-256, 50 MB cap, executable-header block) → local scan in `scanner/engine.py` (heuristics, AV provider, YARA 4 rule files, raw-byte signatures, content rules with encoding normalisation) → local verdict → threat-intel enrichment in `backend/services/threat_intelligence/enrichment.py` (VirusTotal by SHA-256, up to 5 URLs to URLhaus, up to 5 public IPv4s to AbuseIPDB) → deterministic fusion (`fusion.py`) that adds evidence and conflicts but never changes the verdict → dataset status → optional AI analysis behind ALLOW/RESTRICT/BLOCK guardrails → remediation with a stored verification re-scan.

### Existing adapters

| Adapter | Sends | Default | Unavailable states handled | Notes |
|---|---|---|---|---|
| ClamAV (`av_providers/clamav.py`) | whole file to clamav-rest (own container or own VM) | on | yes → `CLAMAV_UNAVAILABLE` | Bearer token over HTTPS for the Oracle gateway |
| MetaDefender (`av_providers/metadefender.py`) | SHA-256 only | off | yes; not found = unavailable | Hash-only since gap #17 |
| VirusTotal (`threat_intelligence/virustotal.py`) | SHA-256 only | off | 401/403/404/429/timeout/5xx | Evidence in `threat_intel`, 1 h cache |
| URLhaus (`urlhaus.py`) | URL string | off | 401/403/429/timeout | Frozen; maps `not_found` to `benign` (see §4) |
| AbuseIPDB (`abuseipdb.py`) | public IP (`is_global`) | off | 401/403/429/5xx/timeout | IPv4 only extracted; no reporting |

### Security boundaries in place
Keys only from env or `/etc/secrets`; never in the browser bundle (audit S2). No file to a third party. URLs are never fetched; URLhaus/AbuseIPDB/VT base URLs are fixed. Private and reserved IPs are rejected before AbuseIPDB. Every provider is opt-in and independently switchable; the app works with all of them off (tested).

### Missing or incomplete
- No common provider interface or result-state enum: each adapter has its own status strings.
- No circuit breaker, no request de-duplication across concurrent scans, caches are per-process dicts.
- No response-size limit on provider responses; no retry with backoff (single attempt, which is safe but loses transient results).
- IPv6 indicators are not extracted.
- TI outages add limitations but leave a `clean_verified` verdict untouched (observed in the Docker run). Whether an enabled-but-down provider should block `clean_verified` is a decision for you.
- URLhaus `not_found` → `benign` contradicts the rule "not found is not clean"; it is frozen behaviour, so it is listed here rather than changed.
- Two core defects found during Phase A.5 and not fixed yet (need your approval, they change detection): any `MZ` byte pair after offset 512 is flagged as an embedded PE (every synthetic test CSV became `suspicious`), and XLSX coverage reports `FULL` after reading only the first 10,000 rows.
- `/health` caches AV status for 5 minutes, so it can lag an outage.

### Regressions to guard against when adding providers
More outbound calls per scan (latency on Render's free tier), quota exhaustion turning into constant limitations, rate-limit storms, and providers that silently start submitting samples. Every new adapter must be lookup-only, off by default and covered by the provider test list in Phase 8.

### Secrets and infrastructure needed (all yours)
Oracle VM + DNS + `SCAN_GATEWAY_TOKEN`/`CLAMAV_API_TOKEN`; optional keys: VirusTotal, abuse.ch Auth-Key (URLhaus, ThreatFox, MalwareBazaar), AbuseIPDB, OTX; optional Neon `DATABASE_URL` and R2 credentials.

## 1. Provider comparison

| Provider | Free API | What Aegis could send | Documented free limits | Automation / commercial | Shared or public? | Source |
|---|---|---|---|---|---|---|
| AbuseIPDB | yes (Individual plan) | public IP | 1,000 IP checks & reports/day; 100 block checks/day; 5 blacklist downloads/day | commercial terms not stated on the pricing page | lookups are not published | https://www.abuseipdb.com/pricing |
| VirusTotal | yes (Community key) | SHA-256 | 500 requests/day, 4/minute | "must not be used in commercial products or services" | uploads are shared with the community; hash lookups do not upload | https://docs.virustotal.com/reference/public-vs-premium-api |
| MalwareBazaar | yes, Auth-Key | SHA-256, TLSH | fair use; numbers not verified | free under fair use (abuse.ch terms); commercial not verified | — | abuse.ch pages did not resolve on 17 Oct 2026 (DNS failure from two networks); not verified |
| ThreatFox | yes, Auth-Key | hash, domain, IP:port, URL | not verified | as above | — | not verified (same DNS failure) |
| URLhaus (existing) | yes, Auth-Key | URL | not verified | as above | — | not verified (same DNS failure) |
| AlienVault OTX | yes, API key | IP, domain, URL, hash | not verified (docs page is a JavaScript app and did not render) | not verified | pulses are community-published | https://otx.alienvault.com/api (not readable) |
| PhishTank | lookup API + local database | URL | rate-limited; HTTP 509 when exceeded; limit shown in headers; descriptive User-Agent required | terms hosted by Cisco, not read | — | https://phishtank.org/api_info.php |
| Shodan | "All Shodan accounts come with a free API plan"; free credits not stated | public IP | free credits not verified; cheapest paid plan $69/month, 10,000 query credits | commercial use listed only for paid plans | — | https://account.shodan.io/billing |
| urlscan.io | search + submission | URL (search), URL (submission) | quotas per account, on the quotas page | — | public scans appear on the front page and in search; unlisted ones are visible to vetted vendors; private only for you | https://urlscan.io/docs/api/ |
| Hybrid Analysis | key required | hash (search), file (submission) | not verified (docs page did not render) | not verified | submissions may be public (not verified) | https://www.hybrid-analysis.com/docs/api/v2 |
| ANY.RUN | Community plan | file/URL via web UI | REST API listed "from 1,500 requests/mo per team", plan not stated | Community = "Personal license"; private analyses only on paid tiers | Community analyses are public | https://any.run/plans/ |
| Joe Sandbox | Cloud Basic | file/URL | not verified (403) | not verified | not verified | joesandbox.com user guide (403) |
| Hunter.io | 50 credits/month | email/domain | 50 credits/month | outreach/cold-email product | — | https://hunter.io/pricing |
| CIRCL hashlookup | yes, no key shown | MD5/SHA-1/SHA-256 | none stated; best effort; offline Bloom filter ~700 MB monthly | free | known-good only; a match "does not show whether the file is malicious" | https://www.circl.lu/services/hashlookup/ |

## 2. Decision matrix (proposed, needs your approval)

| Provider | Decision | Reason |
|---|---|---|
| ClamAV (Oracle) | **IMPLEMENT** (done) | Real signature engine; the only thing that sees file contents, on your own VM |
| URLhaus | **KEEP** | Frozen, lookup-only; fix the `not_found → benign` mapping only with your OK |
| AbuseIPDB | **KEEP** | 1,000 checks/day covers 5 IPs per scan; add IPv6 extraction later |
| VirusTotal | **KEEP, academic only** | Hash lookup only; the terms forbid commercial products, so it must stay off in any commercial deployment |
| MalwareBazaar | **IMPLEMENT** (after terms check) | Hash and TLSH lookups add family/tag evidence; same Auth-Key as URLhaus |
| ThreatFox | **IMPLEMENT** (after terms check) | IOC lookups for the URLs/IPs/hashes Aegis already extracts |
| CIRCL hashlookup | **IMPLEMENT** | Known-good annotation that may never downgrade a local malicious verdict; no key |
| AlienVault OTX | **DEFER** | Overlaps URLhaus/ThreatFox/AbuseIPDB; limits and terms not verifiable today |
| PhishTank | **DEFER** | Useful only if URL evidence is common in your datasets; registration status not verified |
| Shodan | **EXCLUDE** for now | Host metadata is not evidence a file is malicious; free credits not stated, commercial use paid-only |
| urlscan.io | **MANUAL_ONLY** | Search could be added later; submission makes URLs public or visible to vendors |
| Hybrid Analysis | **MANUAL_ONLY** | Report lookup possible in principle; terms and limits not verified; never auto-submit |
| ANY.RUN | **MANUAL_ONLY** | Community analyses are public and personal-licence only |
| Joe Sandbox | **MANUAL_ONLY** | Terms not verifiable; community analyses may be public |
| Hunter.io | **EXCLUDE** | Email discovery for outreach; extracting emails from user datasets would be people-search |

Before any IMPLEMENT row is built: re-read the abuse.ch terms and API pages when they resolve again, and record the numbers here.
