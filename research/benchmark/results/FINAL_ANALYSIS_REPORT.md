# Aegis Node Phase 2: Final Comparative Analysis (A → F)

## 1. Overall A→F Progression

| Metric | A (Base) | B (YARA) | C (Norm) | D (Semantic) | E (ThreatIntel) | F (LLM) |
|---|---|---|---|---|---|---|
| **Accuracy** | 0.795 | 0.795 | 0.846 | 0.923 | 1.000 | 1.000 |
| **Precision** | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| **Recall** | 0.556 | 0.556 | 0.667 | 0.833 | 1.000 | 1.000 |
| **F1** | 0.714 | 0.714 | 0.800 | 0.909 | 1.000 | 1.000 |
| **FPR** | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| **FNR** | 0.444 | 0.444 | 0.333 | 0.167 | 0.000 | 0.000 |

## 2. LLM Validity & Failure Rate (Variant F)

To avoid selection bias, LLM evaluation incorporates invalid outputs and provider failures.

- **Total F Cases Evaluated**: 39
  - **Successful Valid Responses**: 25 (64.1%)
  - **Invalid Responses (Schema Violation)**: 4 (10.3%)
  - **Provider Failures (Content Filter/API)**: 10 (25.6%)

## 3. Analysis Quality on Valid Responses

- **Prompt Injection Resistance**: 3/3 valid injection cases properly flagged `llm_prompt_injection=True`.
- **Contradiction Detection**: 1/2 valid contradiction cases properly flagged `llm_contradiction=True`.
- **Evidence Grounding Quality**: Demonstrated via strict JSON adherence where schema was followed; when the model attempted to inject unstructured reasoning into evidence references, the evaluator intentionally trapped it as an `invalid response` rather than allowing ungrounded text.
- **Uncertainty Handling**: (See `L02` in valid dataset) When external intelligence was missing, the LLM correctly synthesized a 'clean/unknown' state rather than inventing a reputation score.

## 4. Layer-by-Layer Contributions

### What did YARA add? (A → B)
- **Contribution**: No additional raw detections in this dataset, but established defense-in-depth and binary pattern recognition (e.g., C03 shellcode pattern) missed by simple heuristics.
### What did Normalization add? (B → C)
- **Contribution**: Significantly improved Recall by exposing encoded payloads (URL encoding, HTML entities) that bypassed raw signature scans.
- **Data**: Recall improved from 0.556 to 0.667.
### What did Semantic Prompt Protection add? (C → D)
- **Contribution**: Solved indirect and embedded prompt injections (P03, P04, P05) by evaluating semantic intent rather than just string-matching known malicious commands.
- **Data**: Recall improved to 0.833.
### What did Threat Intelligence add? (D → E)
- **Contribution**: Detected novel, zero-day indicators (T01) that were locally clean but externally flagged. Handled contradictions (T05) where local heuristics failed.
- **Data**: Recall achieved 1.000 with 0.0 FPR.
### What did the Real LLM add? (E → F)
- **Contribution**: Provided analyst-facing triage summaries, explicit detection of prompt-injection attempts, and logical resolution of contradictory evidence (scanner vs TI). It added interpretability without overriding the authoritative deterministic pipeline.
### What did the LLM NOT improve? (Costs & Limitations)
- **Limitation 1**: The LLM did not improve raw binary classification (Accuracy/Recall remained identical to Variant E). It is an explanation layer, not a primary scanner.
- **Limitation 2**: Significant reliability cost. 14 out of 39 requests failed due to provider strictness or schema violations.
- **Limitation 3**: Latency. Deterministic scans take ~15ms; LLM calls add substantial network and inference latency (averaging >1000ms per case).
