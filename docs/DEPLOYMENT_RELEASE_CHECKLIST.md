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

## Agent-skill security scan
- **Status:** report-only. `.github/workflows/skill-scan.yml` runs SkillSpector statically on the targets in `security/skill_scan_targets.json` and never blocks a merge or deploy.
- **Before a release:** read the job's sanitized summary (or run `python scripts/skill_scan.py --scanner <pinned skillspector> --mode gate` locally). Any target that is not `complete`, and any untriaged HIGH/CRITICAL finding, needs review before release.
- **Blocking:** not yet. Switch the workflow to `--mode gate` only after the owner signs off `security/skill_scan_triage.json`. See `docs/security/SKILL_SECURITY_SCANNING.md`.
- **Separate from datasets:** this scan never changes a dataset verdict and is not part of the Render image.
