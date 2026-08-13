# Aegis Node — M.Tech Thesis Evidence & Technical Validation

**Author**: Siddharth Goud  
**Degree Program**: Master of Technology (M.Tech) in Computer Science & Engineering / Cybersecurity  
**System Title**: Aegis Node — An AI-Assisted Multi-Stage Framework for Secure Dataset Threat Detection, Remediation & Verification  
**Primary Repository Location**: `C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\`  

---

## 1. Research Problem Statement

Modern machine learning (ML), data engineering, and data warehouse pipelines rely heavily on bulk ingestion of tabular and document datasets (CSV, JSON, JSONL, Parquet) supplied by third parties. Current enterprise data security solutions focus almost exclusively on network transport security (TLS) or cloud storage access control (IAM), creating a critical security gap: **the data content itself is rarely inspected for embedded application-layer payloads before ingestion.**

Specific threats include:
1. **CSV Formula Injection**: Excel and Google Sheets formula triggers (`=`, `+`, `-`, `@`, `|`, `DDE()`, `HYPERLINK()`) that execute arbitrary system commands via Dynamic Data Exchange (DDE) when opened by data analysts.
2. **Cross-Site Scripting (XSS)**: Embedded `<script>` tags, `javascript:` protocol handlers, and `eval()`/`exec()` calls inside text attributes.
3. **SQL Injection Payloads**: Malicious SQL fragments (`' OR '1'='1`, `UNION SELECT`) stored in datasets designed to hijack downstream relational database queries.
4. **Binary & Malware Anomalies**: Control byte injections (`\x00`) and executable malware attachments.

Existing signature antivirus scanners (e.g., ClamAV) fail to detect formula injection or SQL payloads inside valid CSV/JSON files, while rule-only static checkers lack contextual explainability and remediation verification.

---

## 2. Proposed System Architecture

Aegis Node introduces a multi-stage, format-aware threat detection, remediation, and verification pipeline designed to operate synchronously within dataset ingestion workflows.

```text
Upload Dataset -> SHA-256 Checksum -> Format & MIME Check -> Stage 1: ClamAV Antivirus -> Stage 2: Rule Engine -> Aggregated Risk Score -> Stage 3: LLM Reasoning -> Stage 4: Deterministic Remediation -> Stage 5: Verification Re-Scan -> Sanitized Download
```

### Key Technical Contributions
1. **Multi-Stage Hybrid Detection**: Combines signature antivirus scanning with deterministic format-aware rule checking.
2. **Privacy-Preserving LLM Evidence Reasoning**: Downstream LLM integration receives *compact scanner findings only* (evidence minimization), avoiding raw file byte transmission or external API privacy leakage.
3. **Format-Aware Deterministic Remediation**: Neutralizes formula triggers via single-quote prefixing (`'=CMD()`), strips HTML script tags, and neutralizes SQL strings without corrupting dataset structural schema.
4. **Automated Verification Re-Scan**: Executes an immediate post-remediation re-scan to calculate quantitative threat reduction percentage before publishing dataset artifacts.

---

## 3. Detection Architecture & Mathematical Risk Model

The detection engine evaluates dataset content through two independent stages:

### Stage 1 — ClamAV Antivirus Daemon
Communicates over TCP port 3310 using the `INSTREAM` protocol. If the daemon returns `FOUND <VirusName>`, the file status is marked `infected` with a critical severity weight.

### Stage 2 — Content Rules Inspection
Inspects up to 10,000 rows of dataset string columns using compiled regular expression patterns.

| Rule ID | Severity | Category | Rule Description & Pattern |
|---|---|---|---|
| `FORM-001` | High | Formula Injection | Cell starts with formula trigger (`^\s*[=+\-@|]`) |
| `FORM-002` | Critical | Formula Injection | DDE command payload (`DDE\(`, `cmd\|`, `powershell\|`) |
| `FORM-003` | High | Formula Injection | External link formula (`HYPERLINK\(`) |
| `SCRP-001` | Critical | Script Injection | HTML `<script>` tag pattern (`<\s*script`) |
| `SCRP-002` | High | Script Injection | `javascript:` protocol handler |
| `SCRP-003` | High | Script Injection | `eval()` or `exec()` function call |
| `SQLI-001` | High | SQL Injection | Classic SQL injection (`'\s*OR\s*'1'\s*=\s*'1`, `; DROP TABLE`) |
| `SQLI-002` | High | SQL Injection | `UNION SELECT` injection pattern |
| `BIN-001` | Medium | Binary Anomaly | Null byte control character (`\x00`) |

### Composite Risk Score Model

The composite risk score $R \in [0, 10]$ is calculated as:

$$R = \min\left(10.0, \sum_{i \in \text{Findings}} w(s_i) + \delta_{\text{ClamAV}} \cdot 5.0\right)$$

where severity weights $w(s)$ are defined as:
- $w(\text{critical}) = 3.5$
- $w(\text{high}) = 2.0$
- $w(\text{medium}) = 1.0$
- $w(\text{low}) = 0.3$
- $\delta_{\text{ClamAV}} = 1$ if ClamAV detects infection, else $0$.

---

## 4. Remediation & Verification Mathematical Model

Remediation applies deterministic, format-aware transformations:
1. **Formula Neutralization**: Prefixing trigger characters with a single quote: `=CMD("calc.exe")` $\rightarrow$ `'=CMD("calc.exe")`.
2. **Script Neutralization**: `<script>alert(1)</script>` $\rightarrow$ `[script_removed]alert(1)[/script_removed]`.
3. **SQL Neutralization**: `' OR '1'='1` $\rightarrow$ `[sql_payload_neutralized]`.

Post-remediation, an automated re-scan evaluates the sanitized artifact to compute the **Threat Reduction Percentage**:

$$\text{Threat Reduction \%} = \begin{cases} 
\max\left(0.0, \min\left(100.0, \frac{R_{\text{orig}} - R_{\text{san}}}{R_{\text{orig}}} \times 100\right)\right) & \text{if } R_{\text{orig}} > 0 \\
100.0 & \text{if } R_{\text{orig}} = 0 \text{ and } N_{\text{rem}} = 0 \\
0.0 & \text{otherwise}
\end{cases}$$

where $R_{\text{orig}}$ is the original risk score, $R_{\text{san}}$ is the sanitized risk score, and $N_{\text{rem}}$ is the number of remaining threat findings.

---

## 5. Experimental Methodology & Quantitative Results

### Benchmark Dataset Corpus
An independent benchmark corpus of **100 synthetic datasets** was constructed:
- **Clean Datasets**: 20 CSV datasets containing standard enterprise records (names, emails, ages, scores).
- **Formula Injection Datasets**: 20 CSV datasets containing Excel/DDE formula payloads.
- **Script Injection Datasets**: 20 CSV datasets containing XSS script tags and protocol handlers.
- **SQL Injection Datasets**: 20 CSV datasets containing SQL injection strings.
- **Mixed Threats Datasets**: 20 CSV datasets containing multi-category threat combinations.

### Quantitative Classification Results

| Detection Mode | TP | TN | FP | FN | Accuracy | Precision | Recall | F1 Score | FPR | Mean Latency | Throughput |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `rule_only` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | **1.22 ms** | 821.4 ds/sec |
| `clamav_only` | 0 | 20 | 0 | 80 | 0.2000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 5.00 ms* | 200.1 ds/sec |
| `combined` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | **1.73 ms** | 577.8 ds/sec |
| `combined_llm` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | **2.37 ms** | 421.7 ds/sec |

*\*Note: ClamAV daemon was offline during benchmark execution, activating the 0.5s connection fallback.*

### Quantitative Remediation Results
- **Total Threat Datasets Evaluated**: 80
- **Total Initial Threat Findings**: 202
- **Total Resolved Findings Post-Remediation**: 164
- **Total Remaining Findings**: 38 (due to complex mixed payload edge cases)
- **Average Threat Reduction Percentage**: **79.41%**
- **100% Remediation Success Rate**: **66.25%** (53 of 80 datasets completely threat-free)
- **Average Remediation Processing Time**: **6.44 ms**

---

## 6. Academic Limitations & Scope Boundaries

1. **Synthetic Corpus Scope**: The quantitative benchmark corpus consists of 100 synthetic datasets generated from standard security templates. Results reflect performance on structured synthetic threat patterns.
2. **EICAR Signature Basis**: Antivirus evaluation relies on standard EICAR test fixtures. Real-world zero-day binary malware is not included.
3. **Rule Alignment**: Benchmark threat patterns align with OWASP CSV injection and XSS guidelines.
4. **Environment Dependency**: ClamAV integration performance depends on local Docker container availability.

---

## 7. Recommended Future Work

1. **Expanded Benchmark Corpus**: Evaluation against a multi-gigabyte real-world public dataset repository (e.g., Kaggle/HuggingFace datasets).
2. **YARA Integration**: Adding custom YARA rules for advanced file signature matching.
3. **Asynchronous Task Queue**: Transitioning from synchronous HTTP processing to Redis/Celery for multi-gigabyte background scans.
