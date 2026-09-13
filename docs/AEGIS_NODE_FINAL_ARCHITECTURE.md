# Aegis Node: Final Architecture

## Overview
Aegis Node is a full-stack security application designed to scan, analyze, and remediate datasets. The system enforces strict defense-in-depth principles, isolating untrusted data and bounding all external interactions.

## Components

### 1. Frontend (Vercel)
- **Framework:** React + Vite
- **Functionality:** Provides the user interface for file upload, scan visualization, Threat Intelligence (TI) provenance, AI guardrail observability, and remediation status.
- **Boundaries:** Communicates strictly with the backend API via REST.

### 2. Backend (Render)
- **Framework:** FastAPI (Python)
- **Functionality:** Orchestrates the security pipeline (Upload -> Deterministic Scan -> TI Fusion -> AI Guardrails -> LLM Analysis -> Remediation -> Verification).
- **Database:** SQLite (local/ephemeral on Render free tier).

### 3. Deterministic Scanner
- **Core:** ClamAV for signature matching.
- **Heuristics:** YARA-inspired rules, binary anomaly detection (e.g., null bytes in text), formula injection detection.
- **Hashing:** SHA-256 for artifact identity.

### 4. Threat Intelligence (TI) Normalization & Fusion
- **Providers:** URLhaus, AbuseIPDB.
- **Fusion:** Normalizes signals into a unified confidence score and `evidence_strength` (Corroborated, Conflicted, Single, No Evidence).

### 5. AI Guardrails
- **Native Pipeline:** Evaluates structured evidence for prompt injection before LLM invocation.
- **States:** ALLOW, RESTRICT, BLOCK.

### 6. LLM Analysis
- **Role:** Assists analysts by explaining findings. NOT the primary malware authority.
- **Routing:** Cloudflare AI Gateway (supports Gemini, Groq, xAI).

### 7. Remediation & Verification
- **Remediation:** Sanitizes threats (e.g., neutralizing script tags or formula injections).
- **Verification:** Mandatory re-scan of remediated artifacts. Must return `clean_verified` to allow download.

## Deployment Architecture
- **Frontend:** Deployed to Vercel.
- **Backend:** Deployed to Render via Docker.
- **AI Gateway:** Cloudflare.
