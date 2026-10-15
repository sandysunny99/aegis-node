# ─── Stage 1: Build React Frontend ───────────────────────────────────────────
FROM node:20-alpine AS frontend-builder

WORKDIR /frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --silent

COPY frontend/ .

# VITE_API_URL="" means same-origin API calls (frontend + backend on same server)
ARG VITE_API_URL=""
ENV VITE_API_URL=$VITE_API_URL

RUN npm run build

# ─── Stage 2: Python Backend + Serve Frontend ─────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# System deps: curl (healthcheck), gcc (native exts), libmagic (MIME detection)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    curl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps (cached layer — only re-runs if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner package and backend source
COPY scanner/ ./scanner/
COPY backend/ .

# Copy built React app — FastAPI will serve it as static files
COPY --from=frontend-builder /frontend/dist ./static/

# Runtime data directories. Compose mounts named volumes at /app/data (artifacts) and
# /app/db (SQLite); both must exist in the image so the volumes inherit aegis ownership.
# Render free tier uses /tmp (ephemeral, no disk required).
RUN mkdir -p /app/data /app/db /tmp/samples /tmp/quarantine /tmp/sanitized /tmp/reports

# ─── Security: run as non-root user (A-001) ───────────────────────────────────
# /tmp is world-writable so the non-root user can still write to it
RUN useradd --no-create-home --shell /bin/false aegis && \
    chown -R aegis:aegis /app
USER aegis

EXPOSE 8000

# Single worker on free tier (limited RAM); increase for paid plans
CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
