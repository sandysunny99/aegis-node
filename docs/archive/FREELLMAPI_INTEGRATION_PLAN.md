# Integration Plan: Provider Error Normalization

This plan outlines the specific, isolated changes required to adapt FreeLLMAPI's error classification concepts into Aegis Node without disturbing the frozen baseline (`fdad586`).

## Objective
Replace generic HTTP strings in `llm_service.py` and provider adapters with a structured taxonomy to improve fallback precision and observability.

## Phase 1: Define Taxonomy (in `llm_service.py`)
Introduce a lightweight Python enum:
```python
from enum import Enum

class AegisProviderErrorType(Enum):
    AUTH_ERROR = "auth_error"
    RATE_LIMIT = "rate_limit"
    SERVER_ERROR = "server_error"
    TIMEOUT = "timeout"
    MODEL_UNAVAILABLE = "model_unavailable"
    UNKNOWN = "unknown"
```

## Phase 2: Update Provider Adapters
Modify error `except` blocks in `cloudflare_provider.py`, `groq_provider.py`, `xai_provider.py`, and `ollama_provider.py` to intercept `httpx.HTTPStatusError`:
- `status_code == 401 | 403` -> `AUTH_ERROR`
- `status_code == 429` -> `RATE_LIMIT`
- `status_code >= 500` -> `SERVER_ERROR`
- `httpx.TimeoutException` -> `TIMEOUT`

Extract `Retry-After` header if present.

## Phase 3: Enhance `_call_provider`
Update the orchestrator in `llm_service.py` to act on these classifications:
- On `AUTH_ERROR`: Log critically and skip retrying this specific key structure.
- On `RATE_LIMIT` / `SERVER_ERROR`: Log the cooldown/retry hint, then cleanly fall back to the next provider.

## Constraints
- **Zero new dependencies.**
- **No changes to Pydantic schemas or database models.**
- **No changes to external APIs or UI.**
- Only perform this integration if explicit authorization is given to modify the frozen baseline.
