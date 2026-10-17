# Signatureless detection and community feeds

Research date: 17 October 2026. Companion to `THREAT_INTELLIGENCE_PROVIDER_AUDIT.md`.

## Five kinds of evidence, kept separate

| Kind | In Aegis today | Never called |
|---|---|---|
| A. Signatures (ClamAV, YARA, known hashes) | ClamAV 1.5.4 with freshclam; YARA 4 rule files (`backend/rules/yara/`); raw-byte MAL rules | — |
| B. Reputation / IOC lookups (URLhaus, AbuseIPDB, VirusTotal, ThreatFox, MalwareBazaar, CIRCL) | URLhaus, AbuseIPDB, VirusTotal (all opt-in) | "signatureless scanning" |
| C. Heuristic / static analysis | entropy, non-printable ratio, packer and injection strings, MIME mismatch (libmagic), PE imports (pefile), base64 payloads, formula/script/SQL rules, encoding normalisation | — |
| D. Dynamic sandbox | none | — |
| E. AI interpretation | advisory, behind guardrails | a detector |

Signatureless detection in Aegis means **C**: structure and behaviour clues that do not depend on a known sample. IOC lookups (B) depend on someone having seen the indicator before, so a fresh dataset usually comes back "not found", which Aegis must show as "not found", never as clean.

## Candidate sources

| Source | Kind | Fits uploaded datasets? | Licence / terms | Decision |
|---|---|---|---|---|
| ClamAV official signatures (freshclam) | A | yes | free, from the ClamAV mirror | **Keep**: the image's own freshclam; no second freshclam (avoids the update lock clash). Version and signature date shown in `/api/v1/version` and `/health/detectors` |
| YARA Forge core pack | A | partly (rules target executables and scripts more than tabular data) | tooling repo GPL-3.0; each rule keeps its own licence (not verified per rule) | **DEFER until approved**: pin one weekly release, record every rule's licence, run it against the clean fixtures for false positives before enabling. Needs your OK because of GPL tooling and mixed rule licences |
| Existing 4 YARA rules | A | yes | own | Keep; never claim more rules than are loaded (`/health/detectors` reports the count) |
| MalwareBazaar / ThreatFox | B | yes, for hashes, URLs, IPs, domains already extracted | abuse.ch fair use; details not verified (site unreachable) | Proposed IMPLEMENT, lookup-only |
| CIRCL hashlookup | B (known-good) | yes, for whole-file hashes | free, best effort | Proposed IMPLEMENT; annotation only |
| PhishTank database | B | only if URL cells are common | Cisco terms not read | DEFER |
| Sigma rules | log events | **no**: "rules apply to log data"; Aegis scans files | DRL 1.1 | EXCLUDE (no log input) |
| Emerging Threats / Suricata | network traffic | **no**: IDS rules match packets, not files | ET Open licence not checked | EXCLUDE |
| MISP feeds | B | possible later | per feed | DEFER |
| Magika, entropy per column, TLSH, oletools, XLSX DDE/external-link checks | C | yes | Apache-2.0 / own / Apache-2.0 / BSD-2 (from the earlier plan; re-check before adding) | Phase C layers, each behind a flag |

## Update, provenance and cache rules for any feed added later

- Pin the version or download date and its SHA-256; replace atomically; keep the previous copy until the new one loads.
- Report a feed older than its expected update interval as `STALE_DATA`, never as a current confirmation.
- Cache lookups by provider and normalised indicator with a TTL; a cached "not found" is still "not found".
- Regression fixtures: the clean fixtures must stay clean, EICAR must still be detected, and every new rule set is run against them before it is enabled.

## Known false-positive problem to fix first (needs approval)

The raw-byte rule MAL-002 flags any `MZ` pair after byte 512 as an embedded PE. In the 512 MB measurement, every synthetic CSV, JSON, Parquet and TXT file was marked `suspicious` for this reason. A dataset with the country code "MZ" (Mozambique) would be too. Proposed fix: require a valid PE header (`e_lfanew` pointing at `PE\0\0`) before reporting, with a failing test first.
