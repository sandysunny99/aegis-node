# Error Handling Analysis: FreeLLMAPI vs Aegis Node

## 1. FreeLLMAPI Error Taxonomy
FreeLLMAPI excels in precise, categorized error parsing across dozens of diverse providers. It distinguishes:
- **429 Too Many Requests:** `RATE_LIMIT_EXCEEDED`
- **500, 502, 503, 504:** `PROVIDER_SERVER_ERROR`
- **408 / Timeout:** `REQUEST_TIMEOUT`
- **401, 403:** `INVALID_CREDENTIALS` (Requires manual key update, removes from active chain)
- **404:** `MODEL_NOT_FOUND`

It also specifically parses the `Retry-After` HTTP header and provider-specific error body prose (e.g., "try again in 17s") to calculate accurate back-off `cooldown_until` timers.

## 2. Aegis Node Current State
Aegis Node currently relies on generic catch-all exception blocks or standard `httpx.HTTPStatusError` captures. It returns human-readable strings (e.g., "Cloudflare Workers AI rate limit / neuron quota reached (HTTP 429)") but does not structurally differentiate these states for the routing engine, except for some early termination logic in `xai_provider.py` on 401/403.

## 3. Adaptation Target
Aegis Node should implement an `AegisProviderErrorType` enum mapping to:
- `AUTH_ERROR` (Abort provider completely)
- `RATE_LIMIT` (Trigger immediate fallback)
- `SERVER_ERROR` (Trigger immediate fallback)
- `TIMEOUT` (Trigger immediate fallback)

Parsing `Retry-After` logic can be selectively ported to improve diagnostic logging, though Aegis does not run long-lived multi-attempt retry loops.
