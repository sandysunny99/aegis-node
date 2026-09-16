# AI Provider Resilience Audit

## 1. Executive Summary
This audit establishes the provider fallback architecture for Aegis Node, reinforcing the Cloudflare AI Gateway as the central abstraction layer. The architecture maintains existing security boundaries, ensuring that provider fallbacks never bypass native guardrails or alter the deterministic nature of the final security verdict.

## 2. Provider Evaluation

### Cloudflare Workers AI
- **Role:** Primary Fallback
- **Characteristics:**
  - Accessible via REST API and Cloudflare AI Gateway.
  - Large model catalog (65+ models).
  - Generous free allocation (10,000 neurons/day).
- **Security Posture:** High. Remains within the existing Cloudflare ecosystem, simplifying routing and credentials.
- **Decision:** **APPROVED** as the primary fallback provider.

### Hugging Face Inference Providers
- **Role:** Experimental / Secondary
- **Characteristics:**
  - Highly restrictive free credits ($0.10/month for free users).
  - Useful for testing but not viable as a reliable free production fallback.
- **Decision:** **REJECTED** for primary/fallback production use. Approved for experimental use only.

### xAI / Grok
- **Role:** Optional Secondary Provider
- **Characteristics:**
  - High capability.
  - Paid usage only (billed per token).
  - External to the Cloudflare native infrastructure.
- **Decision:** **APPROVED** as an optional, controlled secondary provider. Not to be used as a primary free safety fallback.

## 3. Provider Architecture
```text
Render
  ↓
Aegis Input Guardrails (ALLOW / RESTRICT / BLOCK)
  ↓
Cloudflare AI Gateway
  ↓
Primary: Gemini
  ↓
Fallback: Cloudflare Workers AI
  ↓
Optional Secondary: xAI
  ↓
Optional Experimental: Hugging Face
```

### Constraints:
- All providers must use the exact same bounded context, prompt policy, and output schema.
- The provider fallback mechanism must **never** bypass native guardrails.

## 4. Provider Switching Rules
In the event of a provider failure (e.g., Gemini fails):
1. Record the provider failure.
2. Preserve all deterministic evidence.
3. Preserve the exact guardrail state.
4. Invoke the approved fallback (Cloudflare Workers AI) via the Gateway.
5. Validate the fallback response against the exact same schema.
6. **Keep the deterministic verdict unchanged.**

**Strict Negative Constraints:**
- A provider failure must NEVER default to a `CLEAN` verdict.
- A fallback success must NEVER become the authoritative security verdict.

## 5. Security Boundary Verification
The integration of new fallbacks does not alter the core defense-in-depth model:
- The LLM (regardless of provider) acts strictly as an **INTERPRETER**, not a security authority.
- The deterministic scanner (ClamAV + YARA + heuristics) and mandatory verification retain absolute authority.

## 6. Roadmap Updates
- **Phase 8A:** AI Gateway (Existing)
- **Phase 8A.1:** Workers AI fallback (OPTIONAL)
- **Phase 8B:** R2 (DEFERRED)
- All other phases (9.2 - 13) remain strictly **FROZEN**.

## 7. Conclusion
The provider resilience architecture cleanly integrates Cloudflare Workers AI as a fallback without destabilizing the `4e55a0c` release baseline or introducing unnecessary infrastructure complexity.
