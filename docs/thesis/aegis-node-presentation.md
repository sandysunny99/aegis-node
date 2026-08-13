# Aegis Node — M.Tech Defense Presentation Deck

---

## Slide 1: Title
### Aegis Node
**An AI-Assisted Framework for Secure Dataset Threat Detection, Remediation & Verification**

- **Presenter**: Siddharth Goud
- **Degree**: Master of Technology (M.Tech) in Computer Science & Engineering / Cybersecurity
- **Department**: Department of Computer Science & Engineering
- **Date**: August 2026

---

## Slide 2: Problem Statement
### The Data Ingestion Security Gap
- Enterprise ML & analytics pipelines ingest gigabytes of third-party tabular datasets.
- Network security (TLS) and storage access control (IAM) protect data in transit & at rest.
- **Critical Gap**: Dataset *content* is rarely inspected for application-layer payloads prior to ingestion.
- Embedded formula triggers, XSS scripts, and SQL fragments execute inside downstream analyst tools and database queries.

---

## Slide 3: Motivation
### Emerging Tabular Attack Vectors
- **CSV Formula Injection**: Excel `=CMD()` or `DDE()` payloads execute commands when opened by analysts.
- **Cross-Site Scripting (XSS)**: `<script>` tags render inside web UI reporting dashboards.
- **SQL Injection**: Payloads (`' OR '1'='1`) hijack dynamic backend SQL queries during bulk ingestion.
- **Need**: A lightweight, multi-stage ingestion firewall that detects, remediates, and verifies dataset security automatically.

---

## Slide 4: Research Objectives
### System Goals
1. **Multi-Stage Detection Engine**: Combine signature antivirus (ClamAV) with format-aware rule inspection.
2. **Privacy-Preserving AI**: Integrate Gemini 3.6 Flash using an evidence-minimization model (no raw data transmission).
3. **Deterministic Remediation**: Escapes formula triggers (`'=CMD()`) and neutralizes scripts without destroying dataset schema.
4. **Verification Re-Scan**: Automatically measure post-remediation threat reduction %.
5. **Empirical Evaluation**: Benchmark accuracy, latency, and remediation across 100 synthetic datasets.

---

## Slide 5: Existing Limitations
### Gaps in Current Security Solutions
- **Antivirus Scanners (e.g., ClamAV)**: Detect compiled binary viruses, but fail on text-based formula/SQL injection in CSV files.
- **Static Rule Checkers**: Provide fast detection, but lack contextual explainability and risk synthesis.
- **Cloud LLM Security Tools**: Expose private raw data bytes to external APIs and are susceptible to prompt injection.
- **Aegis Node Solution**: Bridges these gaps through a decoupled multi-stage framework.

---

## Slide 6: Proposed System: Aegis Node
### Overview & Value Proposition
- Lightweight FastAPI backend + React Vite frontend + Docker ClamAV daemon.
- Supports CSV, JSON, JSONL, and Parquet formats.
- Guarantees **original file immutability** (`data/samples/` read-only).
- Delivers real-time scanning (< 2 ms) with automated remediation and sanitized artifact downloads.

---

## Slide 7: System Architecture
### Pipeline Flow
```text
Upload -> SHA-256 Checksum -> ClamAV Daemon -> Content Rules -> Risk Model -> Gemini LLM -> Remediation Engine -> Verification Re-scan -> Download
```
- Decoupled REST API services.
- Isolated filesystem directories (`samples/`, `quarantine/`, `sanitized/`).
- SQLite audit persistence for compliance and history logging.

---

## Slide 8: Threat Detection Pipeline
### Multi-Stage Engine Architecture
- **Stage 1 — Signature Virus Scan**: ClamAV TCP client (`INSTREAM` port 3310).
- **Stage 2 — Content Rule Inspector**: 9 compiled regex rules across 4 threat categories.
- **Composite Risk Score $R \in [0, 10]$**:
  $$R = \min\left(10.0, \sum w(\text{sev}) + \delta_{\text{ClamAV}} \cdot 5.0\right)$$
- Verdicts: `clean`, `suspicious`, `malicious`.

---

## Slide 9: Stage 2 — Content Rule Inspector
### Detected Threat Categories & Rules
- **Formula Injection**: `FORM-001` (`=`, `+`, `-`, `@`), `FORM-002` (`DDE`, `cmd|`), `FORM-003` (`HYPERLINK`).
- **Script Injection**: `SCRP-001` (`<script>`), `SCRP-002` (`javascript:`), `SCRP-003` (`eval()`, `exec()`).
- **SQL Injection**: `SQLI-001` (`' OR '1'='1`), `SQLI-002` (`UNION SELECT`).
- **Binary Anomaly**: `BIN-001` (`\x00` null control bytes).

---

## Slide 10: Stage 1 — ClamAV Integration
### Antivirus Daemon Architecture
- Connects over TCP socket `127.0.0.1:3310`.
- Streams file bytes via `INSTREAM` protocol in 4 KB chunks.
- **Graceful Fallback**: 0.5s connection timeout and 5s offline status caching.
- If ClamAV is down, rule inspection completes without crashing the scan pipeline.

---

## Slide 11: Stage 3 — LLM Contextual Analysis
### Privacy-Preserving Gemini Integration
- **Model**: `gemini-3.6-flash` via official `google-genai` SDK v2.
- **Evidence Minimization**: Transmits *compact rule finding dicts only* (rule ID, severity, category, location).
- **Data Isolation**: Raw dataset files, cell strings, database tables, or passwords are **never sent**.
- **Prompt Injection Defense**: Role boundaries enforced; tool calling disabled; Pydantic schema validation.

---

## Slide 12: Stage 4 & 5 — Remediation & Verification
### Safe Transformation & Re-Scan
- **Formula Escaping**: Single-quote prefixing (`=CMD()` $\rightarrow$ `'=CMD()`).
- **Script Neutralization**: `<script>` $\rightarrow$ `[script_removed]`.
- **SQL Neutralization**: `' OR '1'='1` $\rightarrow$ `[sql_payload_neutralized]`.
- **Verification Re-Scan**: Instant automated re-scan computes **Threat Reduction %**:
  $$\text{Threat Reduction \%} = \frac{R_{\text{orig}} - R_{\text{san}}}{R_{\text{orig}}} \times 100\%$$

---

## Slide 13: User Interface & Experience
### React 18 Glassmorphic Dashboard
- Interactive file upload drag-and-drop.
- Real-time risk score gauge & verdict badges.
- Detailed threat findings table.
- AI Analysis Summary card with confidence score and recommendations.
- Remediation card showing Before vs After risk scores and transformation logs.
- Paginated scan audit history table.

---

## Slide 14: Security Controls & Defense-in-Depth
- **Upload Security**: UUID file naming, extension whitelist, 100 MB file size cap.
- **Zero Execution**: Read-only pandas/json parsing; zero `eval()` / `exec()` / subshells.
- **Path Traversal Protection**: Enforced boundary resolution against `data/` subdirectories.
- **Secret Isolation**: `GEMINI_API_KEY` stored exclusively in backend `.env`.
- **Docker Isolation**: ClamAV container bound to `127.0.0.1:3310` interface only.

---

## Slide 15: Experimental Methodology
### Synthetic Benchmark Evaluation Setup
- Corpus: **100 synthetic benchmark datasets**.
- Categories: 20 clean, 20 formula, 20 script, 20 SQL, 20 mixed threats.
- Ground Truth: Independent `ground_truth.json` mapping expected threat status.
- Evaluated across 4 modes: `rule_only`, `clamav_only`, `combined`, `combined_llm`.

---

## Slide 16: Benchmark Evaluation Results
### Detection Accuracy & Performance
- **Rule-Only**: Accuracy 1.0000 | Precision 1.0000 | Recall 1.0000 | F1 1.0000 | Latency **1.22 ms**
- **Combined**: Accuracy 1.0000 | Precision 1.0000 | Recall 1.0000 | F1 1.0000 | Latency **1.73 ms**
- **Throughput**: **577.8 datasets/sec** (Combined mode).
- *Disclaimer*: Metrics represent observed performance on the defined synthetic benchmark corpus.

---

## Slide 17: Remediation Performance Results
### Quantitative Threat Neutralization
- **Total Threat Datasets Remediated**: 80
- **Total Resolved Threat Findings**: **164 of 202** (81.2% finding resolution rate)
- **Average Threat Reduction Percentage**: **79.41%**
- **100% Clean Success Rate**: **66.25%** (53 of 80 datasets completely threat-free)
- **Average Remediation Processing Latency**: **6.44 ms**

---

## Slide 18: Research Limitations & Scope
- **Synthetic Corpus**: Evaluation executed on 100 synthetic test datasets.
- **EICAR Signature Focus**: Antivirus tests use EICAR fixtures rather than live zero-day malware binaries.
- **Rule Boundary**: Pattern rules align with OWASP CSV and XSS guidelines.
- **ClamAV/Gemini Status**: Dependencies degrade gracefully when offline.

---

## Slide 19: Academic Contributions
- Hybrid static-antivirus threat detection architecture for tabular datasets.
- Evidence-minimized privacy-preserving LLM security reasoning framework.
- Deterministic dataset sanitizer with post-remediation re-scan verification.
- Reproducible open-source quantitative benchmarking suite.

---

## Slide 20: Conclusion & Future Work
### Conclusion & Next Steps
- **Conclusion**: Aegis Node successfully delivers a high-throughput (< 2 ms), demonstrable, and academically defensible dataset security framework.
- **Future Research Directions**:
  1. Expansion to multi-gigabyte real-world public dataset repositories.
  2. Integration of custom YARA signatures.
  3. Redis/Celery asynchronous task queues for enterprise bulk processing.

**Thank You! Questions & Discussion.**
