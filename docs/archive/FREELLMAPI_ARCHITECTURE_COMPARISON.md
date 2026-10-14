# Architecture Comparison: FreeLLMAPI vs. Aegis Node

## 1. Domain and Intent
- **FreeLLMAPI:** Designed as a multi-protocol proxy/gateway for bypassing free-tier rate limits during coding agent and experimentation tasks. Maximum flexibility, minimal constraint.
- **Aegis Node:** Designed as a deterministic security application. The LLM layer is strictly bounded, advisory, and downstream of actual threat intelligence sources. Security-first, highly constrained.

## 2. Abstraction vs. Native Implementation
- **FreeLLMAPI:** Implements its own extensive `openai-compat.ts` adapter layer, mapping upstream JSON and SSE streams manually to bypass heavy SDK dependencies.
- **Aegis Node:** Leverages official SDKs (like `google-genai`) and reliable Pydantic wrappers, as the system does not need to expose a generic external `/v1/chat/completions` API.

## 3. Fallback Philosophy
- **FreeLLMAPI:** A massive 20-attempt fallback loop (`fallback-loop.ts`). Iterates through varied providers attempting to find any available capacity. Prioritizes up-time over model consistency.
- **Aegis Node:** Sequential configuration-defined chain. If the primary and declared fallback (e.g., Groq -> Cloudflare) fail, it degrades securely to deterministic output.

## 4. Feature Intersection
FreeLLMAPI includes Fusion mode (parallel fan-out to judge), MCP (JSON-RPC), and Context Handoff (multi-turn conversation state). **None of these belong in Aegis Node.** Aegis Node relies on single-shot, contextually minimal inference requests for explicit dataset threat analysis.

## 5. Security Models
- **FreeLLMAPI:** Focuses on protecting API keys at rest using AES-256-GCM. Has no concept of malicious input or prompt injection.
- **Aegis Node:** Focuses on protecting the execution environment and LLM reasoning engine from malicious dataset content via dual-tier guardrails. Uses environment variables and secret files for keys.
