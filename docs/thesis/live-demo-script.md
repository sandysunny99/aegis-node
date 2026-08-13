# Aegis Node — Viva Live Demonstration Script

**Duration**: 10–15 Minutes  
**Target Audience**: M.Tech Project Defense Panel & Examiners  
**Location**: `C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\`  

---

## 1. Pre-Demo Setup (2 Minutes Before Presentation)

Open three PowerShell terminal windows:

### Terminal 1 — Start ClamAV (Optional)
```powershell
Set-Location "C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node"
docker compose up -d
```

### Terminal 2 — Start Backend API
```powershell
Set-Location "C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\backend"
.venv\Scripts\activate
uvicorn main:app --reload --port 8000
```
*Verify API health:* `http://localhost:8000/health` $\rightarrow$ `{"status": "ok"}`

### Terminal 3 — Start Frontend Dashboard
```powershell
Set-Location "C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\frontend"
$env:PATH = "C:\Users\SIDDHARTH GOUD\.gemini\antigravity\scratch\tools\nodejs\node-v22.17.1-win-x64;$env:PATH"
npm run dev
```
*Open Browser:* `http://localhost:5173`

---

## 2. Step-by-Step Viva Demonstration Protocol

### Step 1 — Introduce Architecture (1 Minute)
- Open `http://localhost:5173` in your web browser.
- Point out the **Aegis Node** title and subtitle: *"AI-Assisted Framework for Secure Dataset Threat Detection, Remediation & Verification"*.
- State to examiners: *"Aegis Node operates as an inline dataset security gateway inspecting CSV, JSON, and Parquet files prior to ingestion into ML or data warehouse pipelines."*

### Step 2 — Upload & Scan Clean Dataset (1 Minute)
- Click **Browse Files** and select `data/benchmarks/clean/clean_001.csv`.
- Click **Upload & Scan Dataset**.
- **Point out to panel**:
  1. Cryptographic SHA-256 hash generation (`a8f3...`).
  2. Instant scan execution (< 2 ms).
  3. Green **Clean Verdict** badge (**Risk Score: 0.0**).
  4. Zero findings detected.

### Step 3 — Upload Threat Dataset (2 Minutes)
- Click **Upload Another File**.
- Select `data/benchmarks/formula_injection/formula_injection_001.csv`.
- Click **Upload & Scan Dataset**.
- **Point out to panel**:
  1. Instant risk score update: **Risk Score: 8.5 (Malicious)**.
  2. Scan Findings table detailing **Rule ID `FORM-001`**, **Severity `high`**, **Location `column='price_formula', row=0`**.
  3. Payload sample: `=CMD("calc.exe")`.
  4. State: *"The engine detected an unescaped Excel DDE formula trigger capable of executing arbitrary commands upon opening in Excel."*

### Step 4 — Trigger AI Contextual Analysis (2 Minutes)
- Click **Analyze with Gemini AI** (or view automated summary card).
- **Point out to panel**:
  1. **AI Verdict**: `malicious` with high confidence score (`0.95`).
  2. **Threat Summary**: Gemini provides structured explanation of DDE execution risks.
  3. **Data Minimization Guarantee**: Open backend terminal logs confirming *only compact rule finding dictionaries* were sent to Gemini (zero raw cell bytes or database tables exposed).

### Step 5 — Execute Deterministic Remediation (2 Minutes)
- Click **Remediate Dataset**.
- **Point out to panel**:
  1. Instant remediation execution (< 10 ms).
  2. **Risk Before vs. Risk After**: `8.5` $\rightarrow$ `0.0`.
  3. **Threat Reduction Percentage**: `100.0%`.
  4. **Transformation Action Log**: Displays `=CMD(...)` escaping to `'=CMD(...)`.

### Step 6 — Verification Re-Scan & Download (2 Minutes)
- Highlight the **Verification Re-scan Status** card:
  - Remaining findings: `0`.
  - Resolved findings: `1`.
- Click **Download Sanitized Dataset**.
- Open downloaded `sanitized_formula_injection_001.csv` in Notepad or Excel.
- **Show examiners**: The cell starts with single quote (`'=CMD(...)`), neutralizing formula execution.
- **Verify Original Immutability**: Show that `data/samples/` original file remains untouched.

### Step 7 — Scan Audit History (1 Minute)
- Click **Scan History** in the navigation header.
- **Show panel**: Table of all historical scan sessions, stored in SQLite database with server-side pagination (limit 20 per page).

### Step 8 — Present Benchmark Evaluation Results (2 Minutes)
- Open `docs/phase-6-evaluation-report.md`.
- **Show panel**:
  1. Empirical benchmark evaluation across **100 synthetic datasets**.
  2. Detection table comparing `Rule-Only`, `ClamAV-Only`, `Combined`, and `Combined+LLM`.
  3. Highlight: **F1 Score 1.0000**, **Average Scan Latency 1.73 ms**, **Average Threat Reduction 79.4%**.
  4. Read disclaimer: *"Metrics reflect performance observed on the defined synthetic benchmark corpus under controlled scientific conditions."*

---

## 3. Concluding Summary (1 Minute)

State to examiners:
> *"In summary, Aegis Node provides a high-throughput, privacy-preserving, and format-aware security framework that detects dataset threats, provides AI-driven explainability without raw data leakage, and deterministically remediates payloads while quantitatively verifying threat reduction."*
