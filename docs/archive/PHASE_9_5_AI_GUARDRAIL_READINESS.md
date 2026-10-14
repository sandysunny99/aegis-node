# Phase 9.5 AI Guardrail Readiness Assessment

## 1. Current Controls
Aegis Node currently employs native architectural guardrails:
- Data extraction isolation (`_build_compact_evidence`) stripping out raw file contents.
- Strict Pydantic output validation ensuring enum adherence for critical fields.
- `_DANGEROUS_PATTERNS` regex output filtering for direct prompt leakage and instruction overrides (e.g. `ignore previous instructions`, `rm -rf`).
- Cloudflare AI Gateway for routing and basic observability.
- Deterministic, LLM-isolated verdict generation and remediation.

## 2. Threat Model
Our Phase 9.5 Threat Model (see `PHASE_9_5_AI_THREAT_MODEL.md`) highlights that the primary residual risk is **Prompt Injection (T1-T7)**.
While the LLM is physically incapable of executing code or altering the local scanner's authoritative verdict, an embedded prompt injection can manipulate the LLM's advisory output (summary, severity, confidence).

## 3. Benchmark Design & Weaknesses
A deterministic local benchmark was created (`tests/benchmark_guardrails.py`) running against 8 benign and 12 adversarial synthetic inputs.

**Results:**
- **False Positives:** 1 / 8 (Legitimate security discussions mentioning `rm -rf` are blocked by rigid regex).
- **Attacks Missed:** 11 / 12 (Base64 encoding, spaced letters, role impersonation, and tool-call faking bypassed the regex completely).
- **Latency Overhead:** < 1 ms (Extremely fast, but semantically blind).

**Weakness:** The current `_DANGEROUS_PATTERNS` regex is brittle. It blocks legitimate security analysis while missing obfuscated or non-literal injection attacks.

## 4. Cloudflare Gateway Assessment
**Status:** PARTIAL.
While `cloudflare_provider.py` routes successfully through Cloudflare AI Gateway (inheriting caching and analytics), the other fallback providers (Groq, xAI, Ollama) directly call their native API endpoints.
**To fix:** Future iterations should route all compatible provider API calls through the AI Gateway universal endpoints. This consolidates rate limiting, logging, and spend controls.

## 5. Framework Evaluation
- **LLM Guard:** The upstream repository (`protectai/llm-guard`) is archived as of July 2026. Without an actively maintained community fork, adopting it introduces unacceptable supply-chain and maintenance risks.
- **NVIDIA NeMo Guardrails:** Provides semantic dialog and prompt injection guardrails but requires a complex programmable architecture (Colang) which is vast overengineering for our non-interactive, single-shot advisory pipeline.
- **Guardrails AI:** Shut down its Hub infrastructure in August 2026. Furthermore, its primary benefit is schema validation, which Aegis already handles robustly with Pydantic.
- **LiteLLM:** Unnecessary duplication, as Cloudflare AI Gateway already fulfills our gateway routing and rate-limiting requirements.

## 6. Recommended Architecture
**OPTION A: Native Aegis guardrails only.**
Due to the archived status of LLM Guard and the architectural mismatch of NeMo/Guardrails AI, we will rely exclusively on native Aegis controls.

**To address the Prompt Injection gap natively:**
Instead of a heavy third-party framework, we will improve our native input/output sanitization:
1. Extend `_DANGEROUS_PATTERNS` or implement lightweight heuristic functions (e.g. entropy checks or base64 decoding checks) directly.
2. Route all providers through Cloudflare AI Gateway.
3. Accept the residual risk that the LLM may hallucinate a summary, relying on the fact that the **LLM remains completely non-authoritative**.

## 7. Measurable Metrics
- Attack detection rate: Currently 1/12 (8.3%).
- False positive rate: Currently 1/8 (12.5%).
- Schema-valid output rate: 100%.

## 8. Dependency / Security Trade-offs
By choosing Option A, we prioritize supply-chain security and architectural simplicity over advanced semantic injection detection. The trade-off is accepting a higher rate of missed prompt injections (which can only affect the advisory text, never the deterministic remediation or verdict).
