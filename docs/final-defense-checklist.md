# Aegis Node — Final Defense Checklist & Viva Q&A Guide

**Project**: Aegis Node — An AI-Assisted Multi-Stage Framework for Secure Dataset Threat Detection, Remediation & Verification  
**Degree**: Master of Technology (M.Tech) in Computer Science & Engineering / Cybersecurity  
**Location**: `C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\`  

---

## 1. M.Tech Defense Evidence Checklist

### Software Architecture Checklist
- [x] Multi-stage scan engine operational (`scanner/engine.py`)
- [x] ClamAV INSTREAM TCP client with graceful offline fallback (`scanner/clamd_client.py`)
- [x] Rule-based content inspector covering formula, script, SQL, and binary threats (`scanner/content_checker.py`)
- [x] Deterministic format-aware sanitizer for CSV, JSON, Parquet (`scanner/sanitizer.py`)
- [x] Privacy-preserving Gemini 3.6 Flash LLM integration (`services/llm_service.py`)
- [x] React 18 + Vite interactive scanning dashboard (`frontend/src/App.jsx`)
- [x] SQLite database audit trail with scan history & pagination (`backend/routers/history.py`)

### Security Controls Checklist
- [x] Strict upload validation (UUID naming, size limits, format allow-list, SHA-256 integrity hash)
- [x] Zero code/command execution (`eval()`, `exec()`, `subprocess` forbidden on uploaded data)
- [x] Original dataset immutability (`data/samples/` and `data/quarantine/` untouched)
- [x] Sanitized artifact isolation (`data/sanitized/`)
- [x] LLM evidence data minimization (raw bytes/tables never sent to external APIs)
- [x] System prompt injection defense & tool/function calling disabled
- [x] Docker socket interface restricted to `127.0.0.1:3310`

### Research & Reproducibility Checklist
- [x] 100 synthetic benchmark datasets generated (`data/benchmarks/`)
- [x] Independent ground truth metadata (`data/benchmarks/metadata/ground_truth.json`)
- [x] 4 detection modes evaluated (`rule_only`, `clamav_only`, `combined`, `combined_llm`)
- [x] Classification metrics computed (Accuracy 1.0000, Precision 1.0000, Recall 1.0000, F1 1.0000, FPR 0.0000)
- [x] Performance metrics computed (Mean scan latency 1.73 ms, 577 datasets/sec throughput)
- [x] Quantitative remediation metrics computed (79.41% average threat reduction, 66.25% success rate)

---

## 2. Viva Defense Questions & Concise Model Answers

### Q1: Why is dataset security important in modern data pipelines?
**Answer**: Enterprise ML and analytics pipelines routinely ingest bulk datasets from third-party sources. Traditional boundary controls (TLS/IAM) protect data in transit and at rest, but fail to inspect data *content*. Embedded formula triggers, XSS scripts, or SQL injection payloads can compromise data analyst workstations, frontend web UI dashboards, or downstream relational database queries.

### Q2: Why combine rule-based content detection and ClamAV signature scanning?
**Answer**: ClamAV excels at detecting known binary malware and virus attachments via signature matching, but cannot detect application-layer tabular threats like CSV formula injection or SQL strings inside text columns. Conversely, static rules detect text payloads rapidly but cannot inspect compiled binary malware. The hybrid pipeline combines both signatures and format-aware rules without single points of failure.

### Q3: What is the exact role of the LLM in Aegis Node?
**Answer**: The Gemini LLM serves as an **analysis and reasoning assistant**, not the primary malware detector. Deterministic rules and ClamAV perform 100% of detection and threat neutralization. The LLM processes compact scanner evidence to generate structured threat summaries, false-positive evaluations, and remediation recommendations.

### Q4: Why is raw dataset content NOT sent to the LLM API?
**Answer**: Transmitting full dataset files to third-party LLM APIs exposes sensitive enterprise data (PII, credentials, proprietary records) and incurs prohibitive token latency/cost. Aegis Node implements **evidence minimization**: only compact finding metadata (rule ID, severity, category, line location) is sent.

### Q5: How is prompt injection prevented when interacting with the LLM?
**Answer**: 
1. Dataset content is never passed directly into prompt instructions.
2. The LLM system prompt enforces strict system role boundaries.
3. Tool/function calling is completely disabled.
4. Output is strictly validated against a Pydantic schema (`LlmAnalysisOutput`).

### Q6: How does deterministic remediation work?
**Answer**: Remediation applies format-aware transformations:
- **Formula Injection**: Single-quote prefixing (`=CMD()` $\rightarrow$ `'=CMD()`) disables formula execution when opened in spreadsheet software.
- **Script Injection**: Converts `<script>` tags to `[script_removed]`.
- **SQL Injection**: Neutralizes SQL string patterns without executing database queries or altering non-threat cells.

### Q7: How is remediation effectiveness measured quantitatively?
**Answer**: Following sanitization, an automated re-scan inspects the sanitized artifact. Threat reduction percentage is calculated as:
$$\text{Threat Reduction \%} = \frac{\text{Risk}_{\text{orig}} - \text{Risk}_{\text{san}}}{\text{Risk}_{\text{orig}}} \times 100\%$$
Aegis Node tracks resolved vs. remaining findings count to verify security improvement empirically.

### Q8: What is the difference between threat detection and remediation?
**Answer**: **Detection** identifies and quantifies the presence of threats, computing a risk score and verdict. **Remediation** transforms the dataset content to neutralize threats and generates a sanitized, usable file artifact while preserving original dataset structure.

### Q9: Why use synthetic benchmark data for evaluation?
**Answer**: Synthetic datasets allow controlled, reproducible experiments with precise ground-truth labels across specific threat categories (formula, script, SQL, clean). Real-world malicious datasets are unsafe to execute or distribute, whereas synthetic inert test strings evaluate scanner accuracy safely.

### Q10: What are the primary academic limitations of this system?
**Answer**:
1. The 100-dataset benchmark corpus uses synthetic inert test strings.
2. Antivirus evaluation relies on the EICAR test signature rather than real zero-day malware binaries.
3. ClamAV integration requires an active local daemon.
4. Measured 100% classification accuracy applies to the defined synthetic corpus, not all real-world data.

### Q11: What happens when the Gemini API is unavailable or unconfigured?
**Answer**: The system degrades gracefully. The scanner engine completes all detection, risk calculation, and remediation workflows normally, while displaying an `"AI Analysis Unavailable"` message without crashing.

### Q12: What happens when the ClamAV daemon is offline?
**Answer**: Aegis Node logs `ClamAV offline — skipping virus stage` and completes the rule-based content scan. The scan report marks `clamav_status: "skipped"`, ensuring dataset processing is not blocked.

### Q13: How is path traversal prevented during file upload and download?
**Answer**: Uploaded files are assigned UUID-based filenames. The `file_service` enforces strict path resolution and boundary checks using `Path.resolve()`, verifying that target paths reside inside designated `data/samples/` or `data/sanitized/` subdirectories.

### Q14: How are original uploaded files protected from accidental modification?
**Answer**: Original uploaded files stored in `data/samples/` (or `data/quarantine/`) are treated as **read-only immutable artifacts**. Remediation engine outputs are saved exclusively to a separate `data/sanitized/` directory under a new UUID filename and distinct SHA-256 checksum.

### Q15: What makes Aegis Node suitable for an M.Tech research project?
**Answer**: Aegis Node combines cybersecurity engineering, AI integration, and empirical software evaluation. It delivers a multi-stage threat detection system backed by quantitative research metrics (precision, recall, F1, scan latency, threat reduction %) tested across a 100-dataset benchmark corpus.
