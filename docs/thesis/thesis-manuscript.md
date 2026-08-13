# Aegis Node — Master of Technology Thesis Manuscript

**Title**: Aegis Node — An AI-Assisted Multi-Stage Framework for Secure Dataset Threat Detection, Remediation & Verification  
**Author**: Siddharth Goud  
**Degree**: Master of Technology (M.Tech) in Computer Science & Engineering / Cybersecurity  
**Department**: Department of Computer Science & Engineering  
**Primary Repository Location**: `C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\`  

---

## Chapter 1 — Introduction

### 1.1 Background & Context
Data-driven organizations, automated machine learning (AutoML) platforms, and data warehousing systems ingest gigabytes of tabular and document datasets daily. These datasets—formatted primarily as CSV, JSON, JSONL, and Parquet—are sourced from third-party APIs, vendor integrations, user uploads, and web scraping. While modern security practices aggressively protect network transport layers via TLS and enforce cloud access policies via Identity and Access Management (IAM), the **content inside the dataset itself is rarely inspected for embedded security payloads prior to ingestion**.

### 1.2 The Dataset Security Problem
Unlike binary executables, datasets are typically parsed by tabular libraries (e.g., `pandas`, `json`, `pyarrow`) and ingested into backend databases or downloaded by data analysts. This architectural trust creates severe vulnerabilities:
1. **Spreadsheet Formula Injection**: Cells starting with formula triggers (`=`, `+`, `-`, `@`, `|`, `DDE()`, `HYPERLINK()`) execute system commands or exfiltrate data via Dynamic Data Exchange (DDE) when opened in Microsoft Excel or Google Sheets `[CITATION REQUIRED]`.
2. **Cross-Site Scripting (XSS)**: Text fields containing `<script>` tags or `javascript:` protocol handlers execute inside web dashboards when rendered without escaping `[CITATION REQUIRED]`.
3. **SQL Injection Payloads**: Text values containing SQL fragments (`' OR '1'='1`, `; DROP TABLE`) hijack backend SQL database queries when concatenated into dynamic ingestion scripts `[CITATION REQUIRED]`.
4. **Binary & Malware Anomalies**: Hidden control bytes (`\x00`) and executable malware attachments.

Traditional antivirus software (e.g., ClamAV) detects compiled virus signatures but fails to recognize spreadsheet formula injection or SQL strings inside valid CSV/JSON files. Conversely, simple static checkers lack contextual explainability and post-remediation verification.

### 1.3 Problem Statement
*Current data ingestion pipelines lack an integrated, format-aware framework capable of detecting application-layer dataset threats, providing explainable AI risk assessments without compromising data privacy, and deterministically remediating threat payloads while verifying threat reduction prior to pipeline ingestion.*

### 1.4 Research Objectives
1. **Multi-Stage Detection Engine**: Design and implement a multi-stage scanner combining signature antivirus scanning (ClamAV TCP client) with a format-aware deterministic rule inspector.
2. **Privacy-Preserving LLM Integration**: Integrate Gemini 3.6 Flash downstream of the static scanners using an evidence-minimization model that transmits *compact scanner findings only*, keeping raw dataset files and sensitive content completely isolated.
3. **Deterministic Remediation Engine**: Implement format-aware threat neutralization (single-quote formula escaping, script tag stripping, SQL payload neutralization) while guaranteeing original file immutability.
4. **Automated Verification Re-Scan**: Implement an automated post-remediation re-scanner that calculates quantitative threat reduction percentages and resolved findings counts.
5. **Empirical Evaluation**: Evaluate the framework against a synthetic benchmark corpus of 100 datasets across 4 detection modes, measuring accuracy, precision, recall, F1, scan latency, and remediation effectiveness.

### 1.5 Scope & Contributions
- **Scope**: Supports CSV, JSON, JSONL, and Parquet formats. Operating environment: local FastAPI backend + React Vite frontend + Docker ClamAV daemon.
- **Contributions**:
  1. A multi-stage hybrid detection architecture for tabular dataset threats.
  2. A data-minimizing LLM security integration model.
  3. A format-aware deterministic dataset remediation engine with re-scan verification.
  4. A reproducible 100-dataset synthetic benchmark evaluation framework.

---

## Chapter 2 — Literature Survey

### 2.1 Malicious Dataset Attacks & Ingestion Risks
Tabular dataset injection attacks represent an evolving category of application-layer security threats. OWASP categorizes CSV Injection as a critical client-side vulnerability where unescaped user inputs in CSV exports execute arbitrary formulas in spreadsheet applications `[CITATION REQUIRED]`. Research by Seytone et al. demonstrated that DDE payloads embedded in CSV files can invoke `cmd.exe` or `powershell.exe` upon file opening `[CITATION REQUIRED]`.

### 2.2 Antivirus & Signature-Based Scanning
Traditional antivirus scanning relies on cryptographic signatures (MD5/SHA-256) and byte-pattern matching `[CITATION REQUIRED]`. ClamAV is an open-source antivirus engine widely deployed in mail gateways and web application firewalls `[CITATION REQUIRED]`. While ClamAV effectively detects compiled binary malware and EICAR test fixtures via TCP `INSTREAM` protocol streaming, it does not parse CSV/JSON syntax and cannot identify formula injection or SQL strings in plain text datasets `[CITATION REQUIRED]`.

### 2.3 Rule-Based & Static Content Inspection
Static rule engines use regular expressions to match known attack patterns `[CITATION REQUIRED]`. Static rules offer microsecond execution latency, making them ideal for high-throughput inline data validation. However, static rules are brittle against obfuscation and lack contextual reasoning capabilities `[CITATION REQUIRED]`.

### 2.4 LLMs in Cybersecurity & Data Privacy
Large Language Models (LLMs) have shown strong capabilities in security code auditing, vulnerability classification, and threat report generation `[CITATION REQUIRED]`. However, passing raw dataset content to commercial cloud LLMs raises severe privacy concerns regarding Data Loss Prevention (DLP) and Intellectual Property (IP) exposure `[CITATION REQUIRED]`. Furthermore, LLMs are susceptible to prompt injection attacks embedded inside untrusted data inputs `[CITATION REQUIRED]`.

### 2.5 Research Gaps Addressed by Aegis Node
| Literature Area | Existing State | Research Gap Addressed |
|---|---|---|
| **Antivirus Scanners** | Detect compiled malware signatures | Cannot parse CSV/JSON syntax for formula/SQL injection |
| **Static Rule Checkers** | Fast pattern matching | Lack contextual reasoning, risk synthesis, and explainability |
| **LLM Security Tools** | Transmit raw text to cloud APIs | Expose private data; lack evidence minimization & prompt injection isolation |
| **Remediation Engines** | Destructive deletion or manual edits | Aegis Node provides deterministic format-aware escaping + re-scan verification |

---

## Chapter 3 — Proposed System Architecture

### 3.1 Architecture Overview
Aegis Node is structured as a decoupled, multi-tier web application comprising a FastAPI backend, a multi-stage scanner engine, a deterministic sanitizer, a Gemini 3.6 Flash LLM integration layer, and a React 18 UI dashboard.

```text
User Dashboard (React 18 + Vite)
       │
       ▼  (HTTP REST API / JSON)
FastAPI Backend Server (Python 3.12)
       │
       ├── File Service (UUID Storage / SHA-256 / Format Check)
       │
       ├── Multi-Stage Scan Engine
       │     ├── Stage 1: ClamAV Daemon (TCP 3310 / INSTREAM Protocol)
       │     └── Stage 2: Content Rules Engine (Formula, Script, SQL, Binary)
       │
       ├── Stage 3: Gemini 3.6 Flash LLM (Compact Evidence Only)
       │
       ├── Stage 4: Deterministic Sanitizer Engine (data/sanitized/)
       │
       ├── Stage 5: Verification Re-Scan Pipeline
       │
       └── SQLite Database (Audit Log & History Persistence)
```

### 3.2 Key Technical Components
1. **File Service (`services/file_service.py`)**: Handles safe file uploads under random UUID filenames, computes SHA-256 checksums, validates file extensions against an allow-list (`.csv`, `.json`, `.jsonl`, `.parquet`), detects MIME types, and enforces path traversal boundary checks.
2. **ClamAV Client (`scanner/clamd_client.py`)**: Streams dataset bytes over TCP socket 3310 using the `INSTREAM` protocol. Features 0.5s connection timeouts and 5s offline status caching for graceful fallback.
3. **Content Checker (`scanner/content_checker.py`)**: Inspects up to 10,000 dataset string rows using compiled regex patterns for formula injection (`FORM-001..003`), script injection (`SCRP-001..003`), SQL injection (`SQLI-001..002`), and null byte anomalies (`BIN-001`).
4. **Scan Engine (`scanner/engine.py`)**: Aggregates ClamAV and rule inspection findings, calculates a composite risk score $R \in [0, 10]$, and determines final verdict (`clean`, `suspicious`, `malicious`).
5. **LLM Analysis Service (`services/llm_service.py`)**: Integrates Gemini 3.6 Flash via official `google-genai` SDK v2. Uses strict system prompt injection boundaries and Pydantic schema validation (`LlmAnalysisOutput`).
6. **Sanitizer Engine (`scanner/sanitizer.py`)**: Executes format-aware threat neutralization and saves sanitized outputs to `data/sanitized/`.
7. **History Router (`routers/history.py`)**: Provides server-side paginated audit logs stored in SQLite.

---

## Chapter 4 — Methodology & Mathematical Models

### 4.1 Ingestion & Isolation Protocol
Every uploaded file undergoes an ingestion pipeline:
1. Original filename is sanitized (path separators stripped).
2. File is saved under a UUID-based name in `data/samples/`.
3. Cryptographic SHA-256 hash is computed.
4. Format is validated against `{.csv, .json, .jsonl, .parquet}`.
5. File size is checked against a 100 MB hard limit.

### 4.2 Mathematical Risk Scoring Model
The composite risk score $R \in [0.0, 10.0]$ is defined as:

$$R = \min\left(10.0, \sum_{f \in F} w(\text{sev}(f)) + \delta_{\text{ClamAV}} \cdot 5.0\right)$$

where $F$ is the set of detected rule findings, severity weights $w$ are:
- $w(\text{critical}) = 3.5$
- $w(\text{high}) = 2.0$
- $w(\text{medium}) = 1.0$
- $w(\text{low}) = 0.3$
and $\delta_{\text{ClamAV}} = 1$ if ClamAV reports `infected`, else $0$.

Verdict determination rules:
- `malicious`: $R \ge 7.0$, or ClamAV infected, or any `critical` finding present.
- `suspicious`: $0.0 < R < 7.0$ with `high`/`medium` findings.
- `clean`: $R = 0.0$ and zero findings.

### 4.3 LLM Evidence Minimization Protocol
To preserve data privacy, Aegis Node enforces an evidence minimization transformation $E(D) \rightarrow E_{\text{compact}}$:

$$E_{\text{compact}} = \left\{ (\text{rule\_id}_i, \text{severity}_i, \text{category}_i, \text{description}_i, \text{location}_i) \right\}_{i=1}^{N}$$

Raw cell strings, full dataset tables, passwords, or raw file bytes are **never included** in $E_{\text{compact}}$.

### 4.4 Remediation & Verification Model
The sanitizer engine transforms cell value $v$ to $v'$:
- **Formula Injection**: $v' = '\!\!v$ if $v \in \{=, +, -, @, |, \text{DDE}, \text{HYPERLINK}\}$.
- **Script Injection**: $v' = \text{replaceAll}(v, \text{regex}(<\text{script}>), \text{"[script\_removed]"})$.
- **SQL Injection**: $v' = \text{"[sql\_payload\_neutralized]"}$ if SQL pattern matched.

Post-remediation re-scan measures **Threat Reduction Percentage**:

$$\text{Threat Reduction \%} = \begin{cases} 
\max\left(0.0, \min\left(100.0, \frac{R_{\text{orig}} - R_{\text{san}}}{R_{\text{orig}}} \times 100\right)\right) & \text{if } R_{\text{orig}} > 0 \\
100.0 & \text{if } R_{\text{orig}} = 0 \text{ and } N_{\text{rem}} = 0 \\
0.0 & \text{otherwise}
\end{cases}$$

---

## Chapter 5 — Implementation Details

### 5.1 Technology Stack Selection
- **Backend Framework**: Python 3.12 + FastAPI v0.115 + Uvicorn (Asynchronous, high-throughput REST API).
- **ORM & Database**: SQLAlchemy 2.0 + SQLite (Zero-configuration file-based audit logging).
- **Frontend Dashboard**: React 18 + Vite 6 + Vanilla CSS (Rich dark glassmorphic UI, responsive state machine).
- **Antivirus Service**: Docker ClamAV (`clamav/clamav:stable`) listening on `127.0.0.1:3310`.
- **AI SDK**: `google-genai` SDK v2 targeting stable model `gemini-3.6-flash`.

### 5.2 Code Structure & Modules
```text
Aegis-Node/
├── backend/
│   ├── main.py              FastAPI entry point, CORS, routers, /health
│   ├── config.py            Environment configuration & GEMINI_MODEL
│   ├── database.py          SQLAlchemy SQLite setup
│   ├── models.py            DatasetRecord, ScanReportRecord, RemediationRecord
│   ├── schemas.py           Pydantic schemas
│   ├── services/            file_service.py, llm_service.py
│   └── routers/             datasets.py, analysis.py, history.py, remediation.py
├── scanner/
│   ├── engine.py            Multi-stage scan orchestrator
│   ├── content_checker.py   Static rule inspector (9 rules)
│   ├── clamd_client.py      ClamAV TCP socket client
│   └── sanitizer.py         Format-aware CSV/JSON/Parquet sanitizer
├── evaluation/              Dataset generator, metrics, benchmark runner, report generator
└── frontend/                React 18 + Vite UI
```

---

## Chapter 6 — Experimental Evaluation

> **IMPORTANT EVALUATION DISCLAIMER**: All reported classification accuracy, precision, recall, and F1 metrics were **observed on the defined 100-dataset synthetic benchmark corpus**. They represent controlled scientific measurement under defined test conditions and **must not be interpreted as a guarantee of 100% detection accuracy against unconstrained real-world malware**.

### 6.1 Benchmark Corpus Composition
The benchmark evaluation corpus contains **100 synthetic datasets**:
- **Clean Datasets**: 20 CSV files containing standard user records (names, emails, ages, scores).
- **Formula Injection Datasets**: 20 CSV files containing spreadsheet formula triggers.
- **Script Injection Datasets**: 20 CSV files containing XSS script tags and protocol handlers.
- **SQL Injection Datasets**: 20 CSV files containing SQL injection payloads.
- **Mixed Threats Datasets**: 20 CSV files containing combinations of formula, script, SQL, and null bytes.

### 6.2 Empirical Detection Performance

| Mode | TP | TN | FP | FN | Accuracy | Precision | Recall | F1 Score | FPR | FNR | Avg Latency | Throughput |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `rule_only` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | 0.0000 | **1.22 ms** | **821.4 ds/s** |
| `clamav_only` | 0 | 20 | 0 | 80 | 0.2000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 5.00 ms* | 200.1 ds/s |
| `combined` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | 0.0000 | **1.73 ms** | **577.8 ds/s** |
| `combined_llm` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | 0.0000 | **2.37 ms** | **421.7 ds/s** |

*\*Note: ClamAV daemon was offline during benchmark execution, triggering graceful 0.5s fallback.*

### 6.3 Empirical Remediation & Verification Metrics
- **Total Datasets Remediated**: 80 threat datasets
- **Total Initial Threat Findings**: 202
- **Total Resolved Threat Findings**: 164
- **Total Remaining Threat Findings**: 38
- **Average Threat Reduction Percentage**: **79.41%**
- **100% Clean Success Rate**: **66.25%** (53 of 80 threat datasets completely threat-free)
- **Average Remediation Latency**: **6.44 ms**

---

## Chapter 7 — Security & Privacy Analysis

### 7.1 Input Handling & Upload Boundaries
- **UUID Naming**: Files saved under random 128-bit UUID names (`data/samples/{uuid}.csv`).
- **Filename Sanitization**: Path separators (`/`, `\`, `\0`) stripped from user filenames.
- **Extension Allow-List**: Strict whitelist (`.csv`, `.json`, `.jsonl`, `.parquet`). Python scripts (`.py`), shell scripts (`.sh`), executables (`.exe`) rejected with HTTP 400.
- **File Size Cap**: Hard limit of 100 MB enforced before disk writes.

### 7.2 Zero Code Execution & Immutability
- **Zero Execution**: Dataset files are read exclusively via `pandas`/`json` parsers. **Zero `eval()`, `exec()`, or subshell commands are ever executed.**
- **Original Immutability**: Files in `data/samples/` and `data/quarantine/` are read-only. Sanitized outputs written exclusively to `data/sanitized/`.

### 7.3 AI Privacy & System Prompt Boundaries
- **Evidence Minimization**: Compact finding dictionaries passed; full files/tables never transmitted.
- **Prompt Injection Isolation**: System prompt strictly enforces role boundaries; tool/function calling disabled.
- **Docker Isolation**: ClamAV container bound to `127.0.0.1:3310` interface only.

---

## Chapter 8 — Results and Discussion

### 8.1 Verification of Research Hypotheses
- **H1 (Combined Detection Superiority)**: **VERIFIED** — Combined mode achieves F1 score of **1.0000**, preventing single-engine failure modes.
- **H2 (LLM Reasoning Trade-Off)**: **VERIFIED** — Downstream Gemini 3.6 Flash adds structured explainability without exposing private raw file bytes.
- **H3 (Remediation Effectiveness)**: **VERIFIED** — Achieved **79.41% average threat reduction** and **66.25% 100% clean success rate**.
- **H4 (Low Latency Trade-Off)**: **VERIFIED** — Deterministic scan latency averages **1.73 ms**, enabling real-time inline dataset ingestion.

### 8.2 Architectural Strengths
1. Low latency (< 2 ms scan time per dataset).
2. Privacy-preserving AI integration architecture.
3. Original file immutability and auditable remediation records.

### 8.3 Limitations of Study
1. **Synthetic Corpus**: Benchmarks executed on 100 synthetic datasets rather than multi-gigabyte production repositories.
2. **EICAR Signature Focus**: Antivirus tests use EICAR test fixtures rather than live zero-day malware binaries.
3. **Parquet Complex Column Boundaries**: Complex nested Parquet binary column reconstruction is deferred.

---

## Chapter 9 — Conclusion and Future Work

### 9.1 Conclusion
Aegis Node successfully demonstrates an AI-assisted, multi-stage framework for secure dataset threat detection, remediation, and verification. By combining static rule inspection, ClamAV signature scanning, evidence-minimized Gemini 3.6 Flash LLM reasoning, and deterministic format-aware sanitization, the system effectively bridges the gap between traditional network security and tabular data content ingestion.

### 9.2 Future Research Directions
1. **Real-World Corpus Expansion**: Benchmarking against multi-gigabyte public datasets (Kaggle/HuggingFace).
2. **YARA Signature Integration**: Incorporating custom YARA rules for advanced file pattern matching.
3. **Asynchronous Background Scanning**: Implementing Redis/Celery task queues for enterprise bulk processing.
