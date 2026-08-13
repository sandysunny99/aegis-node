# Aegis Node — M.Tech Project Demonstration Guide

This guide provides an exact, 10-step sequential walkthrough for demonstrating Aegis Node to project advisors, evaluators, and examiners during an M.Tech viva or project defense.

---

## Prerequisites & Pre-Demo Check

Ensure the application environment is ready:

```powershell
Set-Location "C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node"
backend\.venv\Scripts\pytest.exe tests/ -v
```

Expected result: **46 passed**.

---

## Step 1 — Start the Application Services

### 1. Start ClamAV (Docker Container — Optional)
```powershell
docker compose up -d
```
*(If Docker is not running, Aegis Node gracefully falls back to rule-based scanning).*

### 2. Start Backend API Server
```powershell
cd backend
.venv\Scripts\activate
uvicorn main:app --reload --port 8000
```
*API docs available at:* `http://localhost:8000/docs`

### 3. Start Frontend Dashboard
```powershell
cd frontend
npm run dev
```
*UI Dashboard available at:* `http://localhost:5173`

---

## Step 2 — Upload a Clean Dataset

1. Open `http://localhost:5173` in your browser.
2. Click **Browse Files** and select `data/benchmarks/clean/clean_001.csv`.
3. Click **Upload & Scan Dataset**.
4. **Demonstrate**:
   - Automatic SHA-256 hash calculation (`a8f3...`).
   - Format detection (`csv`).
   - Clean verdict badge (**Clean / Risk 0.0**).
   - Zero threat findings detected.

---

## Step 3 — Upload a Threat Dataset

1. Select `data/benchmarks/formula_injection/formula_injection_001.csv` or `data/benchmarks/script_injection/script_injection_001.csv`.
2. Click **Upload & Scan Dataset**.
3. **Demonstrate**:
   - Instant file upload and SHA-256 generation.
   - High/Critical risk badge update (**Risk 8.5 / Malicious**).
   - Real-time scanner execution (< 5 ms).

---

## Step 4 — Inspect Detailed Threat Findings

1. Scroll to the **Scan Findings** table.
2. **Demonstrate**:
   - **Rule ID**: `FORM-001` (Formula Injection) or `SCRP-001` (Script Injection).
   - **Severity**: `high` or `critical`.
   - **Location**: `column='price_formula', row=0`.
   - **Payload Sample**: `=CMD("calc.exe")` or `<script>alert("XSS")</script>`.

---

## Step 5 — Demonstrate AI Contextual Analysis

1. Click **Analyze with Gemini AI** (or view automated summary).
2. **Demonstrate**:
   - **AI Verdict**: `malicious` with high confidence.
   - **Threat Summary**: Explains *why* `=CMD()` poses an Excel DDE execution threat to data analysts.
   - **Security Recommendations**: Recommends single-quote escaping or CSV sanitizer.
   - **Data Minimization Guarantee**: Show backend logs confirming *only compact rule evidence* was transmitted to Gemini (zero raw file contents exposed).
   - *(If Gemini API key is missing, demonstrate graceful fallback message: "AI Analysis Unavailable")*.

---

## Step 6 — Execute Secure Dataset Remediation

1. Click **Remediate Dataset**.
2. **Demonstrate**:
   - Instant transformation (< 10 ms).
   - **Original Risk vs. Sanitized Risk**: `8.5` $\rightarrow$ `0.0`.
   - **Threat Reduction %**: `100.0%`.
   - **Transformation Action Log**: Shows `=CMD(...)` converted to `'=CMD(...)`.

---

## Step 7 — Verification Re-Scan Evidence

1. Highlight the **Verification Re-scan Status** card.
2. **Demonstrate**:
   - The sanitized artifact is automatically re-scanned upon creation.
   - Remaining findings count: `0`.
   - Resolved findings count: `1`.

---

## Step 8 — Download Sanitized Dataset Artifact

1. Click **Download Sanitized Dataset**.
2. Save and open `sanitized_formula_injection_001.csv` in a text editor or Excel.
3. **Demonstrate**:
   - Cell value is now `'=CMD("calc.exe")` (single-quote prefixed).
   - Opening in Excel displays plain text instead of executing formulas.
   - **Immutability Check**: Verify original file in `data/samples/` remains untouched.

---

## Step 9 — Inspect Historical Scans Audit Trail

1. Click **Scan History** in the navigation header.
2. **Demonstrate**:
   - Table of all previously uploaded datasets.
   - Status badges (`scanned`, `remediated`).
   - Server-side pagination controls (Page size limit 20).
   - Direct link to inspect previous scan reports.

---

## Step 10 — Present Empirical Research Benchmark Results

1. Open `docs/phase-6-evaluation-report.md`.
2. **Demonstrate**:
   - Comparative evaluation across **100 synthetic benchmark datasets**.
   - Performance table comparing `Rule-Only`, `ClamAV-Only`, `Combined`, and `Combined+LLM`.
   - Metrics: **F1 Score 1.0000**, **Average Scan Latency 1.73 ms**, **Average Threat Reduction 79.4%**.
3. Conclude the viva presentation.
