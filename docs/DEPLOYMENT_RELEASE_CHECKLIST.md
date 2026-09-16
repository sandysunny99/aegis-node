# Aegis Node: Deployment Release Checklist

## Vercel (Frontend)
- **Production URL:** `https://aegis-node.vercel.app` (example)
- **Build Command:** `npm run build`
- **Output Directory:** `dist`
- **Environment Configuration:**
  - `VITE_API_BASE_URL`: Bound to Render backend URL.
  - `VITE_TURNSTILE_SITE_KEY`: Public Turnstile key.

## Render (Backend)
- **Service Type:** Web Service
- **Build Command:** `pip install -r requirements.txt` (and ClamAV/YARA setup via Docker/build script if applicable)
- **Start Command:** `uvicorn backend.main:app --host 0.0.0.0 --port $PORT`
- **Environment Configuration:**
  - `ALLOWED_ORIGINS`: Restricted to Vercel production URL.
  - `CLOUDFLARE_AI_GATEWAY_URL`: Configured.
  - API Keys: `GEMINI_API_KEY`, `URLHAUS_API_KEY`, `CLOUDFLARE_TURNSTILE_SECRET_KEY`
- **Health Endpoint:** `/health`
- **Storage:** Ephemeral (SQLite resets on deploy).

## Cloudflare
- **AI Gateway Endpoint:** Configured for routing requests to Gemini/fallback.
- **Rate Controls:** Bound per AI Gateway limits.

## Security
- **API Authentication:** Enforced via keys and Turnstile on mutation endpoints.
- **CORS:** Strictly limited to `ALLOWED_ORIGINS`.
- **Secret Handling:** All secrets are server-only. Frontend receives NO backend secrets.
