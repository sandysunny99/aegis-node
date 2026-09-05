# AI Provider Audit

| Provider | Model | Free Allocation | Status | Default Chain |
|----------|-------|-----------------|--------|---------------|
| **Gemini** | `gemini-2.0-flash` | Yes (per Gemini tier) | **Primary** | `gemini` |
| **Cloudflare Workers AI** | `@cf/meta/llama-3.1-8b-instruct-fast` | 10,000 neurons/day | **Fallback** | `cloudflare` |
| **Ollama** | `llama3.1` (local) | Unlimited (self-hosted) | **Optional** | No |
| **Groq** | `llama-3.1-8b-instant` | Subject to provider terms | **Optional** | No |
| **xAI** | `grok-2-latest` | Paid | **Optional** | No |

## Fallback Logic
The fallback chain is explicitly driven by `AI_PROVIDER` and `AI_FALLBACK_CHAIN`. 
Default: `gemini` -> `cloudflare`. Soft failures (timeout, quota exhausted, unauthorized, unavailable, invalid response) trigger the fallback chain.
