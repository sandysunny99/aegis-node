# Aegis Node: One-Page Summary

## Problem
Modern datasets act as a convergence point for raw data, malicious payloads, and AI manipulation instructions. Existing tools generally treat datasets as opaque files (AV), execute them dangerously (sandboxes), or analyze them using LLMs vulnerable to prompt injection.

## Solution
Aegis Node is an AI-assisted, defense-in-depth dataset security framework. It combines deterministic static analysis, controlled normalization, bounded threat-intelligence enrichment, prompt-injection-aware LLM analysis, controlled remediation, and mandatory post-remediation verification—all without executing untrusted dataset content.

## Architecture & Security
**Core Principle: No single layer is trusted.**
The architecture strictly enforces boundaries:
1. **Upload Validation:** Blocks unsupported binary formats.
2. **Deterministic Scan:** ClamAV + YARA heuristics establish absolute authority.
3. **Normalization:** Decodes obfuscated payloads for static analysis.

## AI & TI
- **Threat Intelligence:** URLhaus and AbuseIPDB provide external evidence via secure, lookup-only integrations (preventing SSRF).
- **AI Guardrails:** Native filters classify input as ALLOW, RESTRICT, or BLOCK, defending against prompt injection.
- **LLM Analysis:** Bounded LLM instances interpret the evidence for analysts but hold **zero security authority** over the final verdict.

## Research & Results
An ablation study (A→F) proved that adding Threat Intelligence (Layer E) achieved perfect classification on a synthetic benchmark, whereas adding the LLM (Layer F) did not improve binary detection. The LLM provided essential contextual interpretation, validating the architectural separation of detection authority and AI interpretation.

## Validation
- **Regression:** 319/319 tests PASS.
- **Deployment:** Validated across Vercel (Frontend), Render (Backend), and Cloudflare AI Gateway.
- **Phase 11 Status:** RELEASE READY WITH DOCUMENTED LIMITATIONS.

## Limitations
- **Guardrails:** Evaluated at 100% on development benchmarks, but 80% detection (20% FPR) on independent holdouts, reinforcing the need for downstream deterministic controls.
- **Remediation:** Limited to structured formats; arbitrary binary remediation is safely unsupported due to upload blocks.
- **No Dynamic Sandboxing:** Intentionally omitted to prioritize safe static analysis.

## Contribution
Aegis Node demonstrates how to safely integrate AI into security pipelines: by using probabilistic models as constrained interpreters while relying on deterministic layers to contain residual uncertainty.
