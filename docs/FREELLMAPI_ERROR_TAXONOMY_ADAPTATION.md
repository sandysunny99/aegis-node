# FreeLLMAPI Error Taxonomy Adaptation

## Objective
Selective adaptation of error-classification and Retry-After parsing concepts from the FreeLLMAPI gateway into Aegis Node, while preserving Aegis's deterministic security boundaries.

## 1. What was borrowed conceptually
- **Typed Error Categories:** Instead of checking for substrings like `"429" in exc_str`, we now map `httpx` status codes to a strict `AegisProviderErrorType` (e.g. `RATE_LIMITED`, `AUTHENTICATION_ERROR`, `TIMEOUT`).
- **Retry-After Header Parsing:** We now safely parse the HTTP `Retry-After` header (both integer seconds and HTTP-date formats).

## 2. What was intentionally NOT copied
- We did **NOT** import the FreeLLMAPI TypeScript monorepo codebase.
- We did **NOT** implement FreeLLMAPI's massive 20-attempt proxy retry loop.
- We did **NOT** implement dynamic model availability scoring.
- We did **NOT** implement the `model="auto"` dynamic provider router.
- We did **NOT** introduce a local SQLite state database to persist provider timeouts across requests.

## 3. Exact Aegis-Native Implementation
- **New File:** `backend/services/llm_error_classifier.py`
  - A small, pure Python 3 module with zero external dependencies (aside from native SDK exceptions like `httpx.HTTPStatusError`).
  - Contains `AegisProviderErrorType` Enum and `classify_error()` function.
  - Implements a bounded delay parser that clamps any `Retry-After` value to a `max_delay` (60 seconds) to prevent unbounded execution hangs.
- **Provider Adapters:** `groq_provider.py`, `cloudflare_provider.py`, `ollama_provider.py`, `xai_provider.py`.
  - Removed their internal error swallowing. They now let `httpx` exceptions bubble up.
- **Service Layer:** `llm_service.py`.
  - Catches the bubbled exceptions centrally in `_call_provider()`.
  - Classifies the error, respects the parsed bounded `Retry-After` delay (by waiting securely if applicable), and then falls back to the next configured fallback provider in the chain if `fallback_eligible` is True.

## 4. Error Categories
- `RATE_LIMITED` (429) -> Retry/Fallback eligible
- `TIMEOUT` (408) -> Retry/Fallback eligible
- `SERVER_ERROR` (5xx) -> Retry/Fallback eligible
- `NETWORK_ERROR` -> Retry/Fallback eligible
- `AUTHENTICATION_ERROR` (401) -> Fallback eligible (skip provider immediately)
- `AUTHORIZATION_ERROR` (403) -> Fallback eligible (skip provider immediately)
- `BAD_REQUEST` (400, 422) -> Halts fallback (usually a schema/system prompt error that will fail everywhere)
- `CONTEXT_LIMIT` (413) -> Halts fallback
- `UNKNOWN_PROVIDER_ERROR` -> Fallback eligible

## 5. Security Implications
- **Zero API Keys in Logs:** `classify_error()` ensures that raw error payload bodies (which sometimes reflect API keys or sensitive dataset fragments) are not leaked into the standardized `ProviderErrorClassification` response.
- **Dataset Content:** Dataset evidence remains strictly isolated as advisory input (`<UNTRUSTED_DATA>`) and is never executed.
- **Deterministic Scanning Unchanged:** The ClamAV/YARA pipeline is entirely unaffected. LLM evaluation remains strictly downstream.

## 6. Dependency Impact
- **Zero** new dependencies were added to `requirements.txt`. The classifier uses standard library `time` and `email.utils`, and inspects existing `httpx` exceptions.

## 7. Deployment Impact
- Fully compatible with the existing Render backend and Vercel frontend. No new services or Redis queues are required.

## 8. Remaining Limitations
- Aegis Node remains stateless. If a provider throws a 429 Rate Limit, we sleep for the `Retry-After` duration during that specific request, but subsequent simultaneous API requests will still hit the provider until they independently fail and wait. (This is intentional to avoid needing Redis/state).
