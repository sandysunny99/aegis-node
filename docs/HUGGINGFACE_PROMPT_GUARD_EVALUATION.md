# Hugging Face Prompt Guard Evaluation

**Model**: `meta-llama/Prompt-Guard-86M`
**Status**: **PENDING EVALUATION — NOT INTEGRATED**

## Objective
Evaluate whether `Prompt-Guard-86M` provides a meaningful improvement to precision, recall, and F1 scores over existing YARA-based `PROMPT-001` and `PROMPT-002` rules for detecting prompt injections in untrusted datasets.

## Constraints & Considerations
1. **Performance/Cost**: Adding a PyTorch/Transformers stack could significantly bloat the Docker image size and RAM usage. 
2. **License**: Governed by the Llama 3.2 Community License.
3. **Execution**: The evaluation must operate strictly on short text excerpts/snippets, not the complete dataset upload.
4. **Integration Rule**: A negative result (no significant F1 improvement) must result in a formal REJECTION of the integration. Prompt Guard results will only be used as *evidence/signal* and cannot override deterministic scanner verdicts.

## Evaluation Criteria
- Precision & Recall compared to current regex/YARA rules.
- False Positive Rate (FPR) on benign text inputs.
- Latency added per row/snippet.
- Overall deployment size increase.
