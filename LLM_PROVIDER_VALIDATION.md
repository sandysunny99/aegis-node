# LLM Provider Control Validation

## 1. Current Provider Architecture
- **Primary Provider**: Groq
- **Primary Model**: `openai/gpt-oss-20b`
- **Fallback Chain**: NVIDIA → Cloudflare → Hugging Face → FreeLLMAPI

## 2. AUTO Behavior
In AUTO mode, the LLM orchestration selects the configured primary provider first. If it encounters a retryable or fallback-eligible error, it automatically routes the identical deterministic security context to the next provider in the fallback chain until one succeeds or all fail.

## 3. Manual Behavior
In MANUAL mode, the user selects a specific provider from the allowlisted registry. The orchestrator calls ONLY that provider. If it fails, no silent fallback occurs, and a structured failure is returned to ensure deterministic observability and reproducible research comparisons.

## 4. Fallback Chain
The current verified chain is:
1. Groq
2. NVIDIA
3. Cloudflare
4. Hugging Face
5. FreeLLMAPI (Terminal Fallback)

## 5. FreeLLMAPI Terminal Fallback
FreeLLMAPI is integrated as the final node in the fallback chain (if configured/enabled), used only as a last resort to relieve capacity limitations from primary commercial APIs. It handles rate limits and availability errors identically to primary providers.

## 6. Error Taxonomy
Errors are strictly classified via `services/llm_error_classifier.py`:
- `RATE_LIMITED` (HTTP 429) -> Retryable / Fallback eligible
- `TIMEOUT` -> Retryable / Fallback eligible
- `SERVER_ERROR` (HTTP 5xx) -> Retryable / Fallback eligible
- `AUTHENTICATION_ERROR` / `AUTHORIZATION_ERROR` (HTTP 401/403) -> Not retryable, but fallback eligible.
- `BAD_REQUEST` (HTTP 400/422) -> Not retryable, fallback eligible.
- `CONTEXT_LIMIT` (HTTP 413) -> Not retryable, fallback eligible.

## 7. Quota/Rate-Limit Behavior
When a provider returns a 429 or quota exhaustion error, the error classifier flags it as fallback-eligible. The loop marks the provider as soft-failed, logs the `fallback_reason` as `rate_limited` or `quota_exhausted`, and transitions immediately to the next provider without blocking or executing time.sleep().

## 8. Test Matrix

| Scenario | Expected | Observed | Status |
|----------|----------|----------|--------|
| AUTO + Primary success | final_provider = primary, fallback_used = False | final_provider = groq, fallback = False | PASS |
| AUTO + Primary 429 | fallback to next provider | fallback to nvidia | PASS |
| AUTO + Primary quota exhausted | fallback_reason = quota_exhausted | fallback_reason = quota_exhausted | PASS |
| AUTO + Primary fails, NVIDIA succeeds | final_provider = nvidia | final_provider = nvidia | PASS |
| AUTO + Primary & NVIDIA fail, CF succeeds | final_provider = cloudflare | final_provider = cloudflare | PASS |
| AUTO + All primaries fail, HF succeeds | final_provider = huggingface | final_provider = huggingface | PASS |
| AUTO + All fail, FreeLLMAPI configured | final_provider = freellmapi | final_provider = freellmapi | PASS |
| AUTO + All fail, FreeLLMAPI disabled | structured LLM failure | status = unavailable | PASS |
| MANUAL + success | only selected provider called | only groq attempted | PASS |
| MANUAL + failure | no auto fallback | status = unavailable | PASS |
| MANUAL + Unknown provider | rejected with validation error | rejected | PASS |

## 9. Exact Automated Test Result
`343 passed, 1 warning in 50.12s` (16 new LLM tests added).

## 10. Real Provider Smoke-Test Result
The local deployment successfully connects to the Groq API (openai/gpt-oss-20b) using the configured `GROQ_API_KEY`, routing through the AI trust boundary and receiving the standard structured JSON threat evaluation. 

## 11. Known Provider Limitations
- The fallback chain is sequential and prioritized by `config.py`.
- FreeLLMAPI is subject to third-party availability and strict rate limits, thus correctly placed as the terminal fallback.
- Context window limitations (HTTP 413) cause a fallback, but downstream providers with similar window limits may also fail identically on massive evidence payloads.
