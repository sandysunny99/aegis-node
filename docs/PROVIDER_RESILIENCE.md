# Provider Resilience Architecture

## Overview
Aegis Node has been updated with a robust multi-provider AI resilience extension to ensure high availability for contextual threat analysis. The AI layer is strictly downstream of the deterministic security scanners.

## Fallback Chain
The AI provider strategy cascades through the following providers automatically:
1. **Groq** (Primary) - `openai/gpt-oss-20b`
2. **NVIDIA NIM** (Direct Fallback) - `meta/llama-3.1-8b-instruct`
3. **Hugging Face** (Direct Fallback) - `meta-llama/Meta-Llama-3.1-8B-Instruct`
4. **Cloudflare Workers AI** (Direct Fallback) - `@cf/meta/llama-3.1-8b-instruct-fast`
5. **xAI / Grok** (Optional) - `grok-3-mini`
6. **Ollama** (Optional Local) - `llama3.1`
7. **FreeLLMAPI** (Optional Terminal Gateway) - `auto`

## Principles
1. **Engineering Resilience, Not Scientific Modification**: Provider diversity ensures the application handles API rate limits gracefully without 500 errors. It does not alter the scientific A-F experimental baseline or deterministic scanning logic.
2. **Deterministic Authority**: The local ClamAV/YARA scanners remain the absolute security authority. The AI provides contextual explanation.
3. **OpenAI-Compatible Protocols**: Integration relies entirely on native `httpx` HTTP requests following OpenAI-compatible structures, avoiding heavy third-party framework dependencies.
4. **Safe Fallback**: Any soft error (e.g. rate limit, 429) triggers immediate failover to the next provider. Hard errors or exhaustion result in a clean degradation to deterministic-only reporting.
