# Aegis Node — Research Results Summary

**Project Location**: `C:\Users\SIDDHARTH GOUD\Downloads\Aegis-Node\`  
**Benchmark Artifacts Source**: `data/benchmarks/results/benchmark_results.json` & `benchmark_results.csv`  
**Generated Date**: August 8, 2026  

---

## 1. Executive Summary

This document summarizes the empirical research evaluation results produced by running the Aegis Node Phase 6 comparative benchmark suite (`python -m evaluation.benchmark_runner`) against **100 synthetic benchmark datasets** (20 clean, 80 threat).

---

## 2. Detection Performance Metrics

| Mode | TP | TN | FP | FN | Accuracy | Precision | Recall | F1 Score | FPR | FNR | Avg Latency (ms) | Throughput (ds/sec) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| `rule_only` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | 0.0000 | **1.22 ms** | **821.4** |
| `clamav_only` | 0 | 20 | 0 | 80 | 0.2000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 1.0000 | 5.00 ms* | 200.1 |
| `combined` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | 0.0000 | **1.73 ms** | **577.8** |
| `combined_llm` | 80 | 20 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | **1.0000** | 0.0000 | 0.0000 | **2.37 ms** | **421.7** |

*\*Note: ClamAV daemon was offline during benchmark execution, activating the 0.5s connection fallback.*

---

## 3. Remediation & Verification Metrics

| Metric | Measured Result |
|---|:---:|
| **Total Datasets Remediated** | 80 |
| **Fully Resolved Datasets (100% Clean)** | 53 |
| **Remediation Success Rate** | **66.25%** |
| **Average Threat Reduction Percentage** | **79.41%** |
| **Total Initial Threat Findings** | 202 |
| **Total Resolved Threat Findings** | **164** |
| **Total Remaining Threat Findings** | 38 |
| **Average Remediation Processing Latency** | **6.44 ms** |

---

## 4. LLM Resource & Token Metrics

| Metric | Measured Result | Status Label |
|---|:---:|---|
| **LLM Requests Executed** | 0 | *Not evaluated — API key unavailable* |
| **Input Tokens Consumed** | 0 | *Not evaluated — API key unavailable* |
| **Output Tokens Consumed** | 0 | *Not evaluated — API key unavailable* |
| **Total Tokens Consumed** | 0 | *Not evaluated — API key unavailable* |
| **Average LLM Latency** | 0.0 ms | *Not evaluated — API key unavailable* |

> **Evaluation Note**: When `GEMINI_API_KEY` is omitted from the environment, Aegis Node handles the condition gracefully without crashing, falling back to deterministic scanner evidence reporting.
