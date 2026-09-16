# Final Re-Audit: Configuration

| Variable | Class | Fallback Safe | Notes |
|----------|-------|---------------|-------|
| `GEMINI_API_KEY` | SECRET | Yes | Handled safely in memory. |
| `CLOUDFLARE_AI_GATEWAY_URL` | SECRET | Yes | |
| `URLHAUS_API_KEY` | OPTIONAL | Yes | Passive lookups still work. |
| `ALLOWED_ORIGINS` | REQUIRED | Yes | Enforces Vercel frontend CORS. |

All secrets remain strictly server-side. Missing secrets degrade gracefully.
