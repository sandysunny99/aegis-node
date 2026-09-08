# Aegis Node Benchmark — Variant B Results

**Git Commit**: `3f440ee`
**Timestamp**: 2026-09-05T18:29:34.776359+00:00
**Python**: 3.12.10
**Total Cases**: 39

## Binary Classification (CLEAN vs SUSPICIOUS/MALICIOUS)

| Metric | Value |
|--------|-------|
| Accuracy | 0.7949 |
| Precision | 1.0000 |
| Recall | 0.5556 |
| F1 Score | 0.7143 |
| False Positive Rate | 0.0000 |
| False Negative Rate | 0.4444 |

## Confusion Matrix (Binary)

| | Predicted Positive | Predicted Negative |
|---|---|---|
| **Actual Positive** | TP=10 | FN=8 |
| **Actual Negative** | FP=0 | TN=21 |

## Multiclass Confusion Matrix

| Expected \ Predicted | CLEAN | SUSPICIOUS | MALICIOUS |
|---|---|---|---|
| **CLEAN** | 21 | 0 | 0 |
| **SUSPICIOUS** | 8 | 8 | 1 |
| **MALICIOUS** | 0 | 0 | 1 |

## Per-Category Accuracy

| Category | Total | Correct | Accuracy |
|----------|-------|---------|----------|
| A: Benign | 5 | 5 | 1.0000 |
| B: Malware Reference | 2 | 2 | 1.0000 |
| C: Malicious Payload | 3 | 3 | 1.0000 |
| D: Formula Injection | 2 | 1 | 0.5000 |
| E: Prompt Injection | 2 | 2 | 1.0000 |
| F: Encoded Content | 1 | 1 | 1.0000 |
| G: Mixed | 1 | 1 | 1.0000 |
| H: Edge Cases | 4 | 4 | 1.0000 |
| L: L | 3 | 2 | 0.6667 |
| N: N | 3 | 2 | 0.6667 |
| P: P | 7 | 3 | 0.4286 |
| T: T | 6 | 4 | 0.6667 |

## Latency

| Metric | Value (ms) |
|--------|-----------|
| Mean | 10.4 |
| Median | 15 |
| P95 | 16 |
| Min | 0 |
| Max | 16 |

## Error Analysis

| Case | Expected | Predicted | Type | Reason |
|------|----------|-----------|------|--------|
| D01 | SUSPICIOUS | MALICIOUS | classification_ambiguity | classification_boundary_ambiguity |
| N01 | SUSPICIOUS | CLEAN | false_negative | no_detection_rule_matched |
| P03 | SUSPICIOUS | CLEAN | false_negative | no_detection_rule_matched |
| P04 | SUSPICIOUS | CLEAN | false_negative | no_detection_rule_matched |
| P05 | SUSPICIOUS | CLEAN | false_negative | no_detection_rule_matched |
| P06 | SUSPICIOUS | CLEAN | false_negative | no_detection_rule_matched |
| T01 | SUSPICIOUS | CLEAN | false_negative | detection_rule_matched_but_severity_insufficient |
| T05 | SUSPICIOUS | CLEAN | false_negative | no_detection_rule_matched |
| L03 | SUSPICIOUS | CLEAN | false_negative | detection_rule_matched_but_severity_insufficient |

## Individual Results

| Case | Expected | Predicted | Correct | Verdict | Findings | Latency (ms) |
|------|----------|-----------|---------|---------|----------|-------------|
| A01 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| A02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| A03 | CLEAN | CLEAN | ✅ | clean_with_limitations | 1 | 0 |
| A04 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 15 |
| A05 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| B01 | CLEAN | CLEAN | ✅ | clean_with_limitations | 3 | 16 |
| B02 | CLEAN | CLEAN | ✅ | clean_with_limitations | 3 | 0 |
| C01 | MALICIOUS | MALICIOUS | ✅ | malicious | 2 | 15 |
| C02 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 0 |
| C03 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 16 |
| D01 | SUSPICIOUS | MALICIOUS | ❌ | malicious | 2 | 0 |
| D02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 14 |
| E01 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 16 |
| E02 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 2 | 0 |
| F01 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 1 | 16 |
| G01 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 5 | 15 |
| H01 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 0 |
| H02 | CLEAN | CLEAN | ✅ | clean_with_limitations | 0 | 16 |
| H03 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| H04 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 15 |
| N01 | SUSPICIOUS | CLEAN | ❌ | clean_verified | 0 | 0 |
| N02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| N03 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 1 | 0 |
| P01 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 14 |
| P02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| P03 | SUSPICIOUS | CLEAN | ❌ | clean_verified | 0 | 0 |
| P04 | SUSPICIOUS | CLEAN | ❌ | clean_verified | 0 | 16 |
| P05 | SUSPICIOUS | CLEAN | ❌ | clean_verified | 0 | 15 |
| P06 | SUSPICIOUS | CLEAN | ❌ | clean_verified | 0 | 0 |
| P07 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| T01 | SUSPICIOUS | CLEAN | ❌ | clean_with_limitations | 2 | 16 |
| T02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 0 |
| T03 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 15 |
| T04 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 0 |
| T05 | SUSPICIOUS | CLEAN | ❌ | clean_verified | 0 | 16 |
| T06 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 14 |
| L01 | SUSPICIOUS | SUSPICIOUS | ✅ | suspicious | 1 | 0 |
| L02 | CLEAN | CLEAN | ✅ | clean_verified | 0 | 16 |
| L03 | SUSPICIOUS | CLEAN | ❌ | clean_with_limitations | 2 | 16 |
