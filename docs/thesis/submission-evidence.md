# Aegis Node — Thesis Submission Evidence Checklist

This checklist enumerates all physical evidence artifacts (screenshots, terminal logs, benchmark output files, and verification records) required prior to final thesis binding and submission.

---

## 1. User Interface & Dashboard Screenshots

- [ ] **Capture 01**: Aegis Node Main Upload Dashboard (`http://localhost:5173`).
- [ ] **Capture 02**: Clean Dataset Upload & Scan Result (**Clean Verdict Badge / Risk 0.0**).
- [ ] **Capture 03**: Threat Dataset Upload & Scan Result (**Malicious Verdict Badge / Risk 8.5**).
- [ ] **Capture 04**: Scan Findings Table detailing Rule ID, Severity, Category, Location, and Sample payload.
- [ ] **Capture 05**: Gemini LLM AI Analysis Summary Card with verdict, confidence score, summary, and recommendations.
- [ ] **Capture 06**: Remediation Card showing Before vs After risk scores (`8.5` $\rightarrow$ `0.0`) and threat reduction percentage (`100.0%`).
- [ ] **Capture 07**: Transformation Action Log table showing `=CMD()` escaped to `'=CMD()`.
- [ ] **Capture 08**: Verification Re-Scan Card showing zero remaining findings and resolved findings count.
- [ ] **Capture 09**: Download Sanitized Dataset File prompt saving `sanitized_formula_injection_001.csv`.
- [ ] **Capture 10**: Downloaded Sanitized File opened in Notepad/Excel demonstrating single-quote formula escaping.
- [ ] **Capture 11**: Scan Audit History Table view with server-side pagination controls.

---

## 2. Terminal & Runtime Environment Screenshots

- [ ] **Capture 12**: Backend Uvicorn Server execution log (`uvicorn main:app --reload --port 8000`).
- [ ] **Capture 13**: FastAPI Interactive OpenAPI Documentation page (`http://localhost:8000/docs`).
- [ ] **Capture 14**: Frontend Vite Development Server execution log (`npm run dev`).
- [ ] **Capture 15**: Docker ClamAV Container status (`docker compose ps`).
- [ ] **Capture 16**: Pytest Test Suite execution output (**46 passed**).
- [ ] **Capture 17**: Ruff Linter execution output (**All checks passed**).
- [ ] **Capture 18**: Frontend Production Build output (`npm run build`).

---

## 3. Benchmark & Research Evidence Files

- [ ] **Capture 19**: Benchmark execution terminal log (`python -m evaluation.benchmark_runner`).
- [ ] **Capture 20**: Generated `data/benchmarks/results/benchmark_results.json`.
- [ ] **Capture 21**: Generated `data/benchmarks/results/benchmark_results.csv`.
- [ ] **Capture 22**: Generated `data/benchmarks/results/remediation_results.json`.
- [ ] **Capture 23**: Generated `docs/phase-6-evaluation-report.md`.
- [ ] **Capture 24**: Git log output (`git log -5 --oneline`) verifying commit history.

---

## 4. Physical Submission File Audit

Verify that the following documentation files exist in `docs/` and `docs/thesis/` before printing:

- [x] `README.md`
- [x] `docs/demo-guide.md`
- [x] `docs/thesis-evidence.md`
- [x] `docs/research-results-summary.md`
- [x] `docs/final-project-status.md`
- [x] `docs/final-defense-checklist.md`
- [x] `docs/project-inventory.md`
- [x] `docs/thesis/abstract.md`
- [x] `docs/thesis/keywords.md`
- [x] `docs/thesis/thesis-manuscript.md`
- [x] `docs/thesis/diagrams.md`
- [x] `docs/thesis/aegis-node-presentation.md`
- [x] `docs/thesis/viva-questions.md`
- [x] `docs/thesis/live-demo-script.md`
- [x] `docs/thesis/research-tables.md`
- [x] `docs/thesis/submission-evidence.md`
