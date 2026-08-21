# Aegis Node — Render Production Deployment Audit

**Date**: August 2026  
**Auditor**: DevOps Engineer & Application Security Architect  
**Target Platform**: Render.com Docker Web Service  
**Repository**: [sandysunny99/aegis-node](https://github.com/sandysunny99/aegis-node)  

---

## 1. Cloud Architecture & Container Runtime

Aegis Node is packaged as a unified multi-stage Docker container serving both the React 18 frontend (Vite compiled static bundle served via FastAPI StaticFiles SPA routing) and the FastAPI asynchronous backend on a single web port (`PORT=8000` / `$PORT`).

```
                ┌──────────────────────────────────────────────┐
                │          Render Load Balancer (TLS)          │
                └──────────────────────┬───────────────────────┘
                                       │ (Port 443 -> Port 8000)
                                       ▼
                ┌──────────────────────────────────────────────┐
                │         Aegis Node Docker Container          │
                │ ┌───────────────────┐  ┌───────────────────┐ │
                │ │  React 18 SPA     │  │  FastAPI Backend  │ │
                │ │  (StaticFiles /)  │  │  (/api/v1/*)      │ │
                │ └───────────────────┘  └───────────────────┘ │
                │           │                     │            │
                │           └──────────┬──────────┘            │
                │                      ▼                       │
                │             /app/data (SQLite WAL)           │
                │       (Persistent Disk / Ephemeral Fallback) │
                └──────────────────────────────────────────────┘
```

---

## 2. Configuration & Security Audit Checklist

| Component / Setting | Configuration Value | Security & Reliability Assessment |
|---|---|---|
| **Health Check Endpoint** | `GET /health` | **PASS**: Returns HTTP 200 `{"status": "healthy", "version": "1.0.0"}` without exposing internal paths, DB connection strings, or secrets. |
| **Container Privilege** | `USER aegis` (UID 10001) | **PASS**: Unprivileged execution prevents container escape and root access. |
| **Upload Size Boundary** | `MAX_UPLOAD_SIZE_MB = 50` | **PASS**: Memory usage is $O(1)$ (0.14 MB peak) due to direct disk streaming. Files > 50 MB return HTTP 413. |
| **Database Persistence** | SQLite (`/app/data/aegis_node.db`) | **PASS**: Configured with WAL mode (`PRAGMA journal_mode=WAL`), `PRAGMA synchronous=NORMAL`, and busy timeout. Gracefully falls back to `/tmp/data` if `/app/data` is read-only. |
| **Secret Management** | Render Environment Variables + Secret Files | **PASS**: Secret keys (`GEMINI_API_KEY`, `XAI_API_KEY`, `GROQ_API_KEY`) can be provided via environment variables or Render Secret Files (`/etc/secrets/*`). |
| **ClamAV Cloud Semantics** | `CLAMAV_HOST=localhost`, `CLAMAV_PORT=3310` | **TRANSPARENT**: In standard Render deployments where ClamAV daemon is absent, the system explicitly reports `CLEAN_WITH_LIMITATIONS` and `CLAMAV_UNAVAILABLE` rather than false certainty. |
| **AI Provider Fallback** | Gemini (Primary) $\rightarrow$ xAI Grok (Fallback) | **PASS**: Auto-failover ensures threat analysis continues if one provider experiences quota limits or network timeouts. |
| **Download Security** | Single-use Cryptographic Tokens | **PASS**: Sanitized dataset downloads require single-use UUID tokens expiring in 60 minutes. |

---

## 3. Ephemeral Storage Behavior Documentation

In cloud container hosting (such as Render free tier without attached persistent disks):
1. Uploaded sample files (`data/samples/`) and sanitized files (`data/sanitized/`) reside in container local storage.
2. In the event of a container restart or redeployment, previous uploaded files are cleared while the application initializes cleanly.
3. **M.Tech Research Applicability**: This behavior is standard and completely acceptable for an interactive dataset scanning and remediation workstation. No enterprise object store (S3) is required for academic demonstration.
