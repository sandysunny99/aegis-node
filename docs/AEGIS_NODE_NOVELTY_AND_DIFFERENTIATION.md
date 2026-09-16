# Aegis Node: Novelty and Differentiation

## A. Existing Capabilities
Aegis integrates established security concepts including ClamAV for signature matching, YARA for heuristics, and external Threat Intelligence via URLhaus and AbuseIPDB. 

## B. Engineering Integration (Key Contribution)
Aegis differentiates itself through its **integration methodology**:
- **Dataset-Centric Pipeline:** It treats data files not just as binary blobs, but as structural artifacts requiring normalization and contextual AI interpretation.
- **Defense in Depth:** The architecture strictly isolates the probabilistic LLM from the deterministic security authority.
- **Safe Static Analysis:** It provides advanced analysis without dynamic execution, eliminating the risks of detonation.
- **Mandatory Verification:** Remediation is coupled with a deterministic re-scan, ensuring closed-loop validation.

## C. Research Contribution
The project provides an **ablation-driven evaluation** (A→F) of security layers. 
- It establishes that LLMs do not inherently improve binary threat detection over robust static + TI pipelines.
- It proves that LLMs introduce value as contextual interpreters, provided they are constrained by prompt-injection guardrails.

## D. Differentiation vs Existing Tools
- **vs Traditional Antivirus:** Aegis provides contextual dataset analysis and AI interpretation.
- **vs Threat Intelligence Aggregators (e.g., VirusTotal):** Aegis is a cohesive pipeline featuring bounded TI fusion, AI guardrails, and deterministic remediation, not just an aggregation platform.
- **vs Dynamic Sandboxes (e.g., ANY.RUN):** Aegis intentionally avoids execution, focusing on safe, rapid static analysis.
- **vs LLM-only Security Analyzers:** Aegis explicitly revokes security authority from the LLM, relying on deterministic layers to prevent prompt injection and hallucination vulnerabilities.
