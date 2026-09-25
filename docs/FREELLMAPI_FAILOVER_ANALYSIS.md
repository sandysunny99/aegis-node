# Failover Analysis: FreeLLMAPI vs Aegis Node

## 1. FreeLLMAPI Fallback Loop
FreeLLMAPI uses a highly aggressive, resilient fallback loop (`fallback-loop.ts`). 
- **Scale:** Attempts up to 20 provider dispatches per request.
- **Dynamic Routing:** Supports `model: "auto"`, scanning a database of 635 models to rank the best candidate dynamically based on latency, capabilities, and provider health.
- **Stateful Cooldowns:** Providers experiencing `429` rate limits are placed in an in-memory penalty box (`cooldown_until`) and skipped in subsequent requests until the timeout expires.

## 2. Aegis Node Fallback Mechanics
Aegis Node uses a conservative, sequential, configuration-driven fallback chain (`_build_provider_chain` in `llm_service.py`).
- **Scale:** Typically 2 to 4 providers (e.g., Primary Groq, fallback Gemini, fallback Cloudflare).
- **Static Routing:** Explicit models and providers mapped in `config.py`.
- **Stateless Execution:** Aegis does not retain rate limit ledger state between independent API requests. It fails fast on individual provider errors and immediately moves to the next in the sequence.

## 3. Analysis & Recommendation
FreeLLMAPI's approach is designed to maintain 100% uptime for high-volume coding agents running on free tiers. Aegis Node runs bounded, low-frequency security scans. 

**Conclusion:** Aegis Node's sequential fallback chain is perfectly suited for its use case. Implementing a 20-step loop or a dynamic scoring engine would introduce unnecessary complexity and latency. The existing `_build_provider_chain` should remain unchanged.
