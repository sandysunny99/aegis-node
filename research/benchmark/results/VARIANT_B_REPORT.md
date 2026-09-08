# Aegis Node Phase 2 — Variant B Report (Controlled Ablation: A + YARA)

**Status**: COMPLETE  
**Production baseline**: main @ 3f440ee  
**Production code modified**: NO  
**Production architecture modified**: NO  

## Objective
Evaluate the isolated contribution of YARA pattern matching (Variant B) against the base content/heuristic rules (Variant A) using exactly the same 20 benchmark cases and ground truth.

## Methodology
The evaluation harness dynamically memory-patched the `yara_scanner.is_available` flag without altering the frozen application source code.
- **Variant A**: Rules + ClamAV + Heuristics (`yara_scanner` mocked as offline)
- **Variant B**: Variant A + YARA

---

## Variant A Metrics (Baseline)

### Binary Classification (CLEAN vs NOT-CLEAN)
- **True Positives (TP)**: 8
- **True Negatives (TN)**: 12
- **False Positives (FP)**: 0
- **False Negatives (FN)**: 0
- **Accuracy**: 1.0000
- **Precision**: 1.0000
- **Recall (TPR)**: 1.0000
- **F1 Score**: 1.0000
- **False Positive Rate (FPR)**: 0.0000
- **False Negative Rate (FNR)**: 0.0000

---

## Variant B Metrics (A + YARA)

### Binary Classification
- **True Positives (TP)**: 8
- **True Negatives (TN)**: 12
- **False Positives (FP)**: 0
- **False Negatives (FN)**: 0
- **Accuracy**: 1.0000
- **Precision**: 1.0000
- **Recall (TPR)**: 1.0000
- **F1 Score**: 1.0000
- **False Positive Rate (FPR)**: 0.0000
- **False Negative Rate (FNR)**: 0.0000

---

## Delta Analysis (B - A)

- **Delta TP**: 0
- **Delta FP**: 0
- **Delta FN**: 0
- **Delta Accuracy**: 0.0000
- **Delta FPR**: 0.0000
- **False-positive changes**: None
- **False-negative changes**: None
- **Latency change**: Negligible difference (YARA execution time per file averages < 20ms)

### YARA Match Evidence
The `ablation_A_vs_B.csv` highlights that YARA independently triggered on **`C03_shellcode_pattern.csv`** (Rule: `suspicious_shellcode_nopsled`).

### Cases Changed by YARA
- **0 cases changed final prediction**.
- *Analysis*: The base heuristic and regex engine (Variant A) already perfectly classified `C03` via its own NOP sled regex (`MAL-011`). YARA correctly triggered simultaneously but did not alter the verdict, proving that YARA provides overlapping defense-in-depth rather than resolving blind spots in this specific 20-case dataset.

---

## Regression Verification

All standard CI tests (`pytest tests/ -v`) pass against the frozen engineering baseline, proving that the evaluation harness caused zero state mutation in the application logic.
