# Aegis Node: Research & Ablation Summary

## Phase 2: A-F Research Pipeline

To determine the value of Large Language Models in security scanning, we evaluated the system through progressive capability ablations (A through F).

### The Layers
- **A = Rules + ClamAV + Heuristics:** The baseline deterministic scanner.
- **B = A + YARA:** (Simulated via heuristic regexes in Node).
- **C = B + Normalization:** Structuring findings cleanly.
- **D = C + Prompt-Injection Defense:** Adding native AI guardrails.
- **E = D + Threat Intelligence:** Adding URLhaus and AbuseIPDB.
- **F = E + Real LLM:** The full production pipeline.

### Findings

The FINAL established metrics demonstrated that:
1. **Binary detection performance** is driven entirely by Layers A, B, and E. 
2. **LLM analyst-assistance behavior** (Layer F) provides summarization, context, and readability, but is fundamentally incapable of reliable binary threat detection.
3. Layer D (Prompt-Injection Defense) is critical to protect Layer F from subversion.

The architecture reflects these findings: Deterministic layers dictate the verdict, while the LLM provides contextual analysis.
