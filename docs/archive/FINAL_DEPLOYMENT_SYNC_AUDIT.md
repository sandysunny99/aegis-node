# Aegis Node Deployment Sync Audit

## 1. Baseline
- **Git SHA:** Pending branch commit.
- **Vercel Configuration:** Default Vite build (`npm run build`, `dist` output).
- **Render Configuration:** Fast API Backend. Ephemeral disk.

## 2. Frontend API Target
- **Environment:** `VITE_API_URL`
- **Fallback:** Defaults to `http://localhost:8000` for local dev.
- **Production Target:** Set inside Vercel Dashboard to point to Render backend URL.

## 3. CORS Configuration
- **Backend:** `ALLOWED_ORIGINS` defaults to wildcard `["*"]` if not explicitly constrained in Render dashboard. Vercel deployment URL should be added to the environment variable.

## 4. Health Check
- Endpoint: `/health` exists and is validated.

## 5. Environment Parity
- **AI Providers:** `GEMINI_API_KEY`, `GROQ_API_KEY`, `XAI_API_KEY`, `CLOUDFLARE_API_TOKEN`
- **TI:** `VIRUSTOTAL_API_KEY`, `URLHAUS_AUTH_KEY`, `ABUSEIPDB_API_KEY`
- **Turnstile:** `CLOUDFLARE_TURNSTILE_SITE_KEY`, `CLOUDFLARE_TURNSTILE_SECRET_KEY`

## 6. Status
- The intended production topology (Vercel Frontend -> Render Backend) remains the source of truth. The earlier `render.yaml` serving both components is deprecated by this configuration, but retained for single-service fallback.
