# AI Guardrail Matrix

| Guardrail | Current implementation | Location | Enforcement point | Fail behavior | Test coverage | Gap | Recommended improvement |
|---|---|---|---|---|---|---|---|
| **INPUT** | | | | | | | |
| Upload size | FastApi UploadFile limits & Nginx config | `backend/routers/datasets.py` / `file_service.py` | Before scanning | 413 Payload Too Large / File Truncation | Yes | None | Maintain native size bounds |
| File validation | Magic byte validation | `backend/services/file_service.py` | Before scanning | 400 Bad Request | Yes | None | Maintain native validation |
| Untrusted content isolation | Explicitly strips raw sample cell contents | `backend/services/llm_service.py: _build_compact_evidence` | Pre-LLM inference | Raw cell data dropped from evidence | Partial | Does not statically scan for prompt injections in metadata (e.g., filename/rule description) | Install LLM Guard input scanner |
| Prompt injection | Dataset text wrapped in `<UNTRUSTED_DATA>` tags. Instruction isolation in system prompt. | `backend/services/llm_service.py: analyse` | Pre-LLM inference | LLM attempts isolation | Partial | Models can sometimes bypass `<UNTRUSTED_DATA>` | Install LLM Guard prompt injection scanner |
| Encoding/obfuscation | None explicitly in AI input stage | N/A | Pre-LLM inference | LLM consumes encoded payload | No | Encoded payloads may bypass tag isolation | Install LLM Guard obfuscation scanner |
| Malformed evidence | Pydantic data extraction | `backend/services/llm_service.py` | Pre-LLM inference | Exception / skipped evidence | Yes | None | None |
| Context-size limits | Output max 4000 chars, findings max 15, truncation | `backend/services/llm_service.py` | Pre-LLM & Post-LLM | Truncation / Fallback to unavailable | Yes | None | None |
| **LLM INPUT** | | | | | | | |
| Prompt injection isolation | System vs User prompt separation | `backend/services/llm_service.py` | Pre-LLM inference | Model specific | Yes | Relies on LLM's adherence to role boundary | Install LLM Guard input scanner |
| System/instruction separation | Separate arguments for `system_prompt` and `user_prompt` | `backend/services/ai_providers/*.py` | Pre-LLM inference | Model specific | Yes | None | None |
| Bounded evidence | Finding fields truncated to 80 chars / 200 chars | `backend/services/llm_service.py: _build_compact_evidence` | Pre-LLM inference | Long payloads truncated | Yes | None | None |
| Secret isolation | Native `.env` abstraction. LLM never receives credentials. | Architecture | Pre-LLM inference | Secrets not present | Yes | Cannot block secrets embedded by users | LLM Guard secret detection |
| Dataset-derived instruction neutralization | `_DANGEROUS_PATTERNS` regex scan on LLM OUTPUT | `backend/services/llm_service.py` | Post-LLM inference | Rejects output returning None | Yes | Heuristic regex is rigid, only checks output | LLM Guard input scanner |
| **LLM OUTPUT** | | | | | | | |
| Schema validation | `LlmAnalysisOutput` Pydantic model | `backend/services/llm_service.py` | Post-LLM inference | Validation error -> AI unavailable | Yes | None | None |
| Enum validation | `Literal["clean", "suspicious"...]` | `backend/services/llm_service.py` | Post-LLM inference | Validation error -> AI unavailable | Yes | None | None |
| Malformed JSON handling | Custom stack-based JSON extractor | `backend/services/llm_service.py: _extract_first_json_object` | Post-LLM inference | Validation error -> AI unavailable | Yes | None | None |
| Excessive output | Hard limit to 4000 chars | `backend/services/llm_service.py` | Post-LLM inference | Truncated payload rejected | Yes | None | None |
| Prompt leakage | Checks output for system prompt revelation | `backend/services/llm_service.py` | Post-LLM inference | Rejects output returning None | Yes | Regex relies on specific strings | LLM Guard output scanner |
| Unsafe recommendation | `_RISKY_ACTION_RE` regex checks for high-risk verbs | `backend/services/llm_service.py` | Post-LLM inference | Prepends `[flagged: ...]` | Yes | Regex relies on specific verbs | LLM Guard output scanner |
| Unsupported claims | Not currently validated for strict entailment | N/A | N/A | Passed to analyst | No | Hallucinated indicators can be accepted | LLM Guard factual consistency check (optional) |
| Hallucinated indicators | Handled via Pydantic schema validation of output structure | `backend/services/llm_service.py` | Post-LLM inference | N/A | Yes | Advanced hallucinations require semantic checks | None |
| **ACTION** | | | | | | | |
| LLM cannot directly execute actions | Architecture isolates LLM from remediation | Architecture | System level | N/A | Yes | None | None |
| LLM cannot directly modify verdict | Final local scanner verdict is isolated from LLM output | Architecture | System level | N/A | Yes | None | None |
| LLM cannot directly call shell | Architecture prevents shell execution by LLM | Architecture | System level | N/A | Yes | None | None |
| LLM cannot directly access filesystem | Architecture prevents filesystem access | Architecture | System level | N/A | Yes | None | None |
| LLM cannot directly perform network requests | Architecture prevents network access | Architecture | System level | N/A | Yes | None | None |
| Remediation policy enforcement | Deterministic remediation code based on threat score | `backend/services/remediation.py` | Post-Analysis | N/A | Yes | None | None |
| Mandatory re-scan | File is rescanned after sanitization | `backend/services/remediation.py` | Post-Remediation | Rollback if threat persists | Yes | None | None |
| Mandatory verification | Integrity verification | `backend/services/remediation.py` | Post-Remediation | Rollback if corrupted | Yes | None | None |
| **INFRASTRUCTURE** | | | | | | | |
| Provider timeout | Timeout config `_call_provider` | `backend/services/llm_service.py` | Network | Fallback / AI Unavailable | Yes | None | None |
| Provider failure | Try/catch around provider call | `backend/services/llm_service.py` | Network | Fallback / AI Unavailable | Yes | None | None |
| Fallback behavior | Multiple providers in chain | `backend/services/llm_service.py` | Network | Failover to next provider | Yes | None | None |
| Rate limiting | FastApi limiter + specific rate-limit handling | `backend/routers/datasets.py` / `llm_service.py` | Network | 429 / Failover to next | Yes | None | Use Cloudflare AI Gateway |
| Logging | `logger.info/error` | `backend/services/llm_service.py` | Observability | N/A | Yes | None | Use Cloudflare AI Gateway for observability |
| Secret handling | Environment variables | `.env` | Env level | API Keys withheld from frontend | Yes | None | None |
| Cloudflare AI Gateway | `ai_providers/cloudflare_provider.py` | API Layer | Gateway Level | Cloudflare handles rate limits/cache | Partial | Only CF is routed through gateway currently | Route all external providers via CF Gateway |
