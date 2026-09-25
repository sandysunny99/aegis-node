# Aegis Node AI Provider Infrastructure Baseline

## 1. Architectural Philosophy
In Aegis Node, the AI layer acts as an **untrusted, contextual reasoning engine downstream of deterministic scanners** (ClamAV, YARA, heuristic engines). It is fundamentally advisory and never serves as the primary security authority. 

## 2. Core Modules
The `backend/services/ai_providers/` package contains:
- `cloudflare_provider.py`: Cloudflare Workers AI integration.
- `groq_provider.py`: Groq Cloud AI integration.
- `ollama_provider.py`: Local Ollama self-hosted inference.
- `xai_provider.py`: xAI / Grok integration.
- *Note:* Google Gemini is implemented directly within `backend/services/llm_service.py` via the `google-genai` SDK.

## 3. Defense-in-Depth Mechanisms
1. **Data Minimization:** Raw file bytes are never passed to the LLM. Only sanitized finding metadata is provided.
    - Max 15 findings included.
    - Findings truncated to 80 chars; descriptions to 200 chars.
2. **Dual-Tier Guardrails:** Pre-invocation semantic analysis against prompt injection, and post-invocation output filtering.
3. **Structured Validation:** Pydantic schema enforcement (`LlmAnalysisOutput`) and bracket-counter fallbacks.
4. **Dangerous Pattern Rejection:** Explicitly rejects outputs matching dangerous commands (e.g., `rm -rf`, `os.system`).

## 4. Fallback Chain
Configured via `ai_fallback_chain` in `config.py`. Ex: `cloudflare,ollama`. Sequential execution, utilizing dedicated `fallback_<provider>_api_key` values. If all fail, the system degrades gracefully and returns a safe deterministic fallback summary.
