# Aegis Node Phase 2 — Variant C Report (Controlled Ablation: B + Normalization)

**Status**: COMPLETE  
**Production baseline**: main @ 3f440ee  
**Production code modified**: NO  
**Production architecture modified**: NO  

## Objective
Evaluate the isolated contribution of the bounded multi-encoding normalization pipeline (Variant C) by comparing it against Variant A (Baseline) and Variant B (+ YARA).

The evaluation dynamically toggles the `normalize_text` logic inside `scanner.content_checker` from the test harness, entirely preserving the frozen production codebase.

## Dataset Expansion (v2)
To provide meaningful discriminatory power for this ablation, the benchmark was expanded from 20 cases (v1) to 23 cases (v2). 

The new cases (`N01`, `N02`, `N03`) safely isolate URL-encoding, Base64-encoding, and Hex-escaping behaviors.
- `N01_encoded_suspicious.csv`: URL/Base64 encoded `<script>` payloads.
- `N02_encoded_benign.csv`: URL/Base64 encoded benign text (`Hello World`).
- `N03_escaped_suspicious.csv`: Hex-escaped `<script>` payloads.

---

## Metrics Comparison (A vs B vs C)

| Metric | Variant A (Baseline) | Variant B (+ YARA) | Variant C (+ Normalization) |
|--------|----------------------|--------------------|-----------------------------|
| **Total Cases** | 23 | 23 | 23 |
| **Accuracy** | 0.9565 | 0.9565 | **1.0000** |
| **Precision** | 1.0000 | 1.0000 | 1.0000 |
| **Recall (TPR)** | **0.8750** | **0.8750** | **1.0000** |
| **FPR** | 0.0000 | 0.0000 | 0.0000 |
| **FNR** | 0.1250 | 0.1250 | **0.0000** |

*Note: Latency across all three variants remains tightly grouped (Mean: ~15ms, P95: ~32ms).*

---

## Ablation Findings: Incremental Value

### 1. New Detections from Normalization
Variant C successfully detected hidden threats that Variant B entirely missed (`B misses -> C detects` = True):
- **`N01_encoded_suspicious.csv`**: Variant B returned `CLEAN` (False Negative). Variant C successfully normalized the URL/Base64 payload and correctly flagged the hidden script injection via `SCRP-001`.

### 2. False Positives Introduced by Normalization
- **None.** The bounded normalizer properly decoded `N02_encoded_benign.csv` (`Hello World`) but safely categorized it as `CLEAN` alongside the rest of the dataset.

### 3. Escalations via Normalization (Hidden Evidence)
Normalization allowed the engine to uncover deeper severity in files that were already partially detected:
- **`F01_encoded_payloads.csv`**: Variant B detected this as `SUSPICIOUS` solely because it possessed a hardcoded regex for Base64 PE headers (`MAL-004`). Variant C, however, recursively normalized the *other* fields in the file, unearthing a URL-encoded Cross-Site Scripting (XSS) payload that triggered the critical `SCRP-001` rule, properly escalating the file to `MALICIOUS`.

### 4. Overlapping Defense-in-Depth
- **`N03_escaped_suspicious.csv`**: This hex-escaped `<script>` tag was caught in Variant B without normalization because the heuristic layer possessed a dedicated signature for hex-encoded shellcode patterns (`MAL-011`). In Variant C, it triggered *both* `MAL-011` (on the raw text) and `SCRP-001` (on the normalized text).

---

## Conclusion

Normalization provides measurable, critical incremental detection value.

Unlike YARA (which provided an overlapping signal in this dataset), the Normalization pipeline independently converted **False Negatives into True Positives** (e.g., `N01`). Furthermore, it did so while maintaining a 0% False Positive Rate, validating the bounded decoding constraints.

The experimental methodology strongly supports activating Normalization in the final Aegis Node threat-detection stack.

## System Integrity Check
- **Production code modified:** NO
- **Regression Tests:** 262/262 PASSED. The core implementation remains perfectly frozen.
