# Aegis Node Benchmark — Variant F Results

**Git Commit**: `3f440ee`
**Timestamp**: 2026-09-05T20:09:49.450430+00:00
**Python**: 3.12.10
**Total Cases**: 39

## Binary Classification (CLEAN vs SUSPICIOUS/MALICIOUS)

| Metric | Value |
|--------|-------|
| Accuracy | 1.0000 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 Score | 1.0000 |
| False Positive Rate | 0.0000 |
| False Negative Rate | 0.0000 |

## Confusion Matrix (Binary)

| | Predicted Positive | Predicted Negative |
|---|---|---|
| **Actual Positive** | TP=18 | FN=0 |
| **Actual Negative** | FP=0 | TN=21 |

## Multiclass Confusion Matrix

| Expected \ Predicted | CLEAN | SUSPICIOUS | MALICIOUS |
|---|---|---|---|
| **CLEAN** | 21 | 0 | 0 |
| **SUSPICIOUS** | 0 | 12 | 5 |
| **MALICIOUS** | 0 | 0 | 1 |

## Per-Category Accuracy

| Category | Total | Correct | Accuracy |
|----------|-------|---------|----------|
| A: Benign | 5 | 5 | 1.0000 |
| B: Malware Reference | 2 | 2 | 1.0000 |
| C: Malicious Payload | 3 | 3 | 1.0000 |
| D: Formula Injection | 2 | 1 | 0.5000 |
| E: Prompt Injection | 2 | 2 | 1.0000 |
| F: Encoded Content | 1 | 0 | 0.0000 |
| G: Mixed | 1 | 0 | 0.0000 |
| H: Edge Cases | 4 | 4 | 1.0000 |
| L: L | 3 | 3 | 1.0000 |
| N: N | 3 | 1 | 0.3333 |
| P: P | 7 | 7 | 1.0000 |
| T: T | 6 | 6 | 1.0000 |

## Latency

| Metric | Value (ms) |
|--------|-----------|
| Mean | 25.9 |
| Median | 16 |
| P95 | 63 |
| Min | 0 |
| Max | 157 |

## Error Analysis

| Case | Expected | Predicted | Type | Reason |
|------|----------|-----------|------|--------|
| D01 | SUSPICIOUS | MALICIOUS | classification_ambiguity | classification_boundary_ambiguity |
| F01 | SUSPICIOUS | MALICIOUS | classification_ambiguity | classification_boundary_ambiguity |
| G01 | SUSPICIOUS | MALICIOUS | classification_ambiguity | classification_boundary_ambiguity |
| N01 | SUSPICIOUS | MALICIOUS | classification_ambiguity | classification_boundary_ambiguity |
| N03 | SUSPICIOUS | MALICIOUS | classification_ambiguity | classification_boundary_ambiguity |

## Individual Results

| Case | Expected | Predicted | Correct | Verdict | Findings | Latency (ms) |
|------|----------|-----------|---------|---------|----------|-------------|
| A01 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 157 |
| A02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| A03 | CLEAN | CLEAN | ✅ | clean_with_limitations | 1 | 47 |
| A04 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| A05 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| B01 | CLEAN | CLEAN | ✅ | clean_with_limitations | 3 | 16 |
| B02 | CLEAN | CLEAN | ✅ | clean_with_limitations | 3 | 30 |
| C01 | MALICIOUS | MALICIOUS | ✅ | malicious | 2 | 14 |
| C02 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 62 |
| C03 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 45 |
| D01 | SUSPICIOUS | MALICIOUS | ❌ | malicious | 2 | 16 |
| D02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| E01 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 16 |
| E02 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 15 |
| F01 | SUSPICIOUS | MALICIOUS | ❌ | malicious | 3 | 61 |
| G01 | SUSPICIOUS | MALICIOUS | ❌ | malicious | 6 | 46 |
| H01 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| H02 | CLEAN | CLEAN | ✅ | clean_with_limitations | 0 | 14 |
| H03 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| H04 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 47 |
| N01 | SUSPICIOUS | MALICIOUS | ❌ | malicious | 1 | 15 |
| N02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| N03 | SUSPICIOUS | MALICIOUS | ❌ | malicious | 2 | 16 |
| P01 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 15 |
| P02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 31 |
| P03 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 0 | 16 |
| P04 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 0 | 16 |
| P05 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 0 | 15 |
| P06 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 16 |
| P07 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 0 |
| T01 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 14 |
| T02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 63 |
| T03 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| T04 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| T05 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 0 | 15 |
| T06 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 0 |
| L01 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 1 | 16 |
| L02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| L03 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 15 |
