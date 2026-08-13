# Aegis Node — Evaluation & Comparative Benchmark Suite

This module provides a reproducible quantitative evaluation framework for measuring the detection accuracy, latency, LLM consumption, and remediation effectiveness of Aegis Node.

---

## 1. Directory Structure

```text
evaluation/
├── __init__.py
├── dataset_generator.py   # Generates 100 synthetic benchmark datasets & ground truth
├── metrics.py             # Classification, performance latency, LLM, and remediation metrics
├── benchmark_runner.py    # Main comparative evaluation engine across all 4 modes
├── report_generator.py    # Exports CSV/JSON results and docs/phase-6-evaluation-report.md
└── README.md              # Reproducibility & usage instructions
```

---

## 2. Detection Modes Evaluated

| Mode | Scanner Pipeline | LLM Integration | ClamAV Integration |
|---|---|---|---|
| `rule_only` | `scanner.content_checker` | Disabled | Disabled |
| `clamav_only` | ClamAV TCP daemon (`clamdscan`) | Disabled | Active |
| `combined` | `content_checker` + `clamd_client` | Disabled | Active |
| `combined_llm` | `content_checker` + `clamd_client` | Gemini 3.6 Flash | Active |

---

## 3. Reproducibility Execution Commands

From the root project directory `C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\`:

### 1. Generate Synthetic Corpus
```powershell
python -m evaluation.dataset_generator
```

### 2. Run Complete Benchmark Suite (Default 100 Datasets)
```powershell
python -m evaluation.benchmark_runner
```

### 3. Run Pytest Test Suite
```powershell
backend\.venv\Scripts\pytest.exe tests/ -v
```

### 4. Run Ruff Linter
```powershell
backend\.venv\Scripts\ruff.exe check backend/ scanner/ tests/ evaluation/
```

### 5. Build Frontend Production Bundle
```powershell
Set-Location frontend
npm run build
```

### 6. Validate Docker Compose Configuration
```powershell
docker compose config
```

---

## 4. Generated Artifacts

Executing the benchmark automatically updates:

- `data/benchmarks/metadata/ground_truth.json` — Ground truth labels
- `data/benchmarks/results/benchmark_results.json` — Machine-readable evaluation JSON
- `data/benchmarks/results/benchmark_results.csv` — CSV metric summary table
- `data/benchmarks/results/remediation_results.json` — Remediation metrics JSON
- `docs/phase-6-evaluation-report.md` — Human-readable markdown research report
