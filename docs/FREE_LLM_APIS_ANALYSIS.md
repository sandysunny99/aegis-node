# Free LLM APIs Repository Analysis

Based on the `awesome-free-llm-apis` repository (https://github.com/mnfst/awesome-free-llm-apis), here is an analysis of the available free API landscape, particularly in relation to Aegis Node's resilience architecture.

## Direct Providers vs Inference Providers
The repository correctly distinguishes between:
1. **Provider APIs** (the model creators themselves): e.g., Google, Cohere, Mistral, Z AI, Aion Labs.
2. **Inference Providers** (third-party hosts of open-weight models): e.g., Groq, NVIDIA NIM, Cloudflare Workers AI, Hugging Face, OpenRouter.

## Key Providers for Aegis Node

### 1. Groq (Primary)
- **Model**: `openai/gpt-oss-20b` or `openai/gpt-oss-120b`.
- **Limits**: 30 RPM, 1,000 RPD, 8K TPM, 200K TPD.
- **Verdict**: Excellent primary choice due to high speed and generous daily request limits for the `gpt-oss-20b` model.

### 2. NVIDIA NIM (Direct Fallback)
- **Model Options**: `openai/gpt-oss-20b`, `mistralai/mistral-large-2-instruct`, `nvidia/nemotron-3-super-120b-a12b`, etc.
- **Limits**: 40 RPM, 10,000 RPD for most models.
- **Verdict**: Strong first fallback. Highly reliable, OpenAI-compatible, and offers very high daily limits (10,000 RPD).

### 3. Cloudflare Workers AI (Direct Fallback)
- **Model Options**: `@cf/meta/llama-3.3-70b-instruct-fp8-fast`, `@cf/openai/gpt-oss-120b`, etc.
- **Limits**: 10,000 Neurons/day free.
- **Verdict**: Great fallback, but limit is measured in "Neurons" rather than raw tokens, meaning larger models consume the daily quota faster.

### 4. Hugging Face (Direct Fallback)
- **Model Options**: `Meta-Llama-3.1-8B-Instruct`, etc.
- **Limits**: $0.10/month in free credits.
- **Verdict**: Good for emergency fallback, but the strict monetary cap makes it less reliable for high-volume daily scanning than NVIDIA or Groq.

### 5. Other Notable Alternatives
- **OpenRouter**: Offers 17 free models (`:free` suffix) like `nvidia/nemotron-3-super-120b-a12b:free`, with limits of 20 RPM / 50 RPD.
- **Mistral AI**: Offers $10/month in API credits and a free mode.
- **Cohere**: Offers a free Trial key (20 RPM) for non-commercial use.

## Recommended Aegis Provider Chain
Based on this analysis, the configured chain is optimal:
`Groq (Primary) -> NVIDIA NIM -> Hugging Face -> Cloudflare -> xAI -> Ollama -> FreeLLMAPI`

NVIDIA is positioned ahead of Hugging Face due to its explicit 10,000 RPD allowance compared to HF's $0.10 limit. FreeLLMAPI remains at the end as a multi-provider router.
