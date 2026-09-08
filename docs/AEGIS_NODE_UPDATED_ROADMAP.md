# Aegis Node Roadmap

**Phase 0 Product definition** — COMPLETE
**Phase 1 Core engineering** — COMPLETE
**Phase 2 Security hardening** — COMPLETE
**Phase 3 Vercel + Render** — COMPLETE
**Phase 4 Release validation** — COMPLETE
**Phase 5 Research benchmark** — COMPLETE
**Phase 6 A-F ablation** — COMPLETE
**Phase 7 Final research analysis** — COMPLETE

---

**Phase 8 Cloudflare infrastructure**
- **8A AI Gateway** — validated (Successful HTTP 200 via `openai/gpt-oss-20b`)
- **8B R2** — DEFERRED / OPTIONAL (Implemented and unit-tested, but live validation is intentionally deferred. Cloudflare R2 is an optional future persistent object-storage backend. Aegis Node currently uses `LocalArtifactStorage` for the academic/demo deployment. The security detection pipeline is storage-provider independent. *Note: Local storage is ephemeral on Render and should not be represented as persistent production artifact storage.*)

---

**Phase 9 External threat intelligence**
Build a clean `ThreatIntelProvider` abstraction mapping providers like VirusTotal, URLhaus, and AbuseIPDB into normalized `ExternalAnalysisEvidence`.

- **9.1 TI audit (VirusTotal)** - COMPLETE
- **9.2 URLhaus integration** - FROZEN (lookup-only)
- **9.3 AbuseIPDB integration** - NOT STARTED
- **9.4 Threat-intelligence fusion hardening** - NOT STARTED
- **9.5 Live TI integration validation** - NOT STARTED

*Current Baseline:*
- Tests = 286/286 PASS
- URLhaus = lookup-only
- R2 = deferred

---

**Phase 10 Optional dynamic-analysis integration**
Incorporate ANY.RUN or compatible sandboxes for optional deep analysis.
**Workflow:** Aegis local scan -> High-risk policy -> Human Authorization -> Sandbox -> Behavioral evidence appended to case.
*Note on ANY.RUN:* Will NOT be used to execute every uploaded file. Aegis remains the static gatekeeper.

---

**Phase 11 Antigravity research/security/diagram tooling**
Integrate specialized tools:
- `diagram-design`: Adopt for architecture/flow diagrams
- `scientific-agent-skills`: Selective research tooling
- `Anthropic-Cybersecurity-Skills`: Selective defensive mapping
- `agentmemory`: Optional Antigravity tool

---

**Phase 12 UI + evidence timeline + case investigation**
SOC-style unified view.
Display verdicts across Local, External Intelligence, and AI Analysis.
Build a linear Evidence Timeline (Upload -> Scan -> TI -> AI -> Remediation -> Verify).

---

**Phase 13 Observability**
Leverage Cloudflare AI Gateway for rate limiting, cache hits, and analytics tracking (AI failure rate, latency).

---

**Phase 14 Final end-to-end validation**
Validate complete pipeline across 10+ edge cases (Formula Injection, Malicious Indicators, R2 failures, etc).

---

**Phase 15 Release / maintenance**
Final release and ongoing tuning.
