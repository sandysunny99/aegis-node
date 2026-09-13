# Aegis Node: Deployment Guide

## Infrastructure Components
- **Frontend:** Vercel
- **Backend:** Render (Docker)
- **AI Routing:** Cloudflare AI Gateway
- **External TI:** URLhaus, AbuseIPDB

## Environment Variables (Required Names)

### Backend (Render)
- `APP_ENV` (set to `production`)
- `AI_PROVIDER`
- `GEMINI_API_KEY` (or other provider keys)
- `ALLOWED_ORIGINS`
- `API_KEY` (for protecting endpoints)
- `DATABASE_URL` (e.g., `sqlite:////tmp/aegis_node.db` on Render free tier)

*(Note: Render free tier uses ephemeral storage. SQLite databases and files in `/tmp` are wiped on restart).*

### AI Gateway
- `CLOUDFLARE_ACCOUNT_ID`
- `CLOUDFLARE_API_TOKEN`

### Frontend (Vercel)
- `VITE_API_BASE_URL` (points to Render backend URL)
