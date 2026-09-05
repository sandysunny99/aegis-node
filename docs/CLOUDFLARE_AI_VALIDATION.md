# Cloudflare AI Validation

## Model Deprecation Decision
The original model `@cf/meta/llama-3.1-8b-instruct` is officially deprecated as of May 30, 2026. 
The validated replacement is `@cf/meta/llama-3.1-8b-instruct-fast`, which provides a 128k context window and remains actively supported by Cloudflare.

## Pricing Verification
The Workers AI free tier provides **10,000 neurons/day**. Usage beyond this allocation incurs costs under the Workers Paid plan. Explicit handling for `QUOTA_EXHAUSTED` (HTTP 429) was introduced to automatically trigger the `AI_FALLBACK_CHAIN`.

## Edge WAF / Proxy Verification
The current Render deployment operates at `aegis-node.onrender.com`. Because DNS proxying is managed by Render, the Cloudflare Edge WAF features (DDoS protection, TLS termination via CF) are **DOCUMENTED ONLY — NOT VERIFIED** for the default deployment. 
To achieve full Edge WAF capabilities, a custom domain must be actively proxied through Cloudflare (orange-cloud).
