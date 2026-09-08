# Cloudflare Enhancement Plan
**Status**: PLAN READY

This document outlines the safe implementation plan for integrating Cloudflare AI Gateway and R2 into the Aegis Node architecture, transitioning the project from Phase 7 (Research Data Freeze) to Phase 8 (Cloudflare Enhancement).

## 1. Current Architecture
Currently, Aegis Node operates as a FastAPI application running on Render, with the following characteristics:
- **LLM Routing**: `backend/services/llm_service.py` directly calls Groq, Gemini, and Cloudflare Workers AI via HTTP requests (`httpx`).
- **File Storage**: Uploaded files, quarantined files, and sanitized artifacts are stored on the ephemeral local filesystem (`data/samples`, `data/quarantine`, `data/sanitized`).
- **Security Storage**: Scan reports and LLM analyses are persisted in a local SQLite database (`data/aegis_node.db`).
- **Turnstile**: Fully integrated and validates tokens against `challenges.cloudflare.com`.

## 2. AI Gateway Proposal
**Objective**: Introduce a unified observability, rate-limiting, and logging layer for all LLM calls without changing provider interfaces.

**Current Flow**: `Aegis → [Groq API / Google API / Workers AI API]`
**Proposed Flow**: `Aegis → Cloudflare AI Gateway → [Groq / Gemini / Workers AI]`

**Implementation Strategy**:
- Update `backend/config.py` to optionally accept `CLOUDFLARE_AI_GATEWAY_URL`.
- Modify `call_groq`, `call_gemini` (and potentially `call_cloudflare` if supported) to conditionally rewrite their endpoint URLs to point to the Gateway if the configuration exists.
- E.g., `https://api.groq.com/openai/v1/chat/completions` becomes `https://gateway.ai.cloudflare.com/v1/{account}/{gateway}/groq/chat/completions`.
- **Preserved Properties**:
  - Structured JSON schemas and `response_format` remain unchanged.
  - The `<UNTRUSTED_DATA>` prompt boundary remains active.
  - The deterministic scanner remains the primary security authority.
  - Provenance tracking (`llm_model_used`, `llm_error`, `latency_ms`) remains untouched.
  - The research fallback behaviors and specific model targets remain intact.

## 3. R2 Proposal
**Objective**: Transition from ephemeral filesystem storage on Render to persistent S3-compatible object storage via Cloudflare R2, preserving artifact integrity.

**Implementation Strategy**:
- Introduce `CLOUDFLARE_R2_BUCKET`, `CLOUDFLARE_R2_ACCESS_KEY_ID`, and `CLOUDFLARE_R2_SECRET_ACCESS_KEY` to `config.py`.
- Create a minimal adapter in `backend/services/file_service.py` that checks if R2 is configured.
  - **Local Mode (Default)**: Write to local `data/` directory (preserves local dev experience).
  - **Production Mode**: Stream uploads directly to R2, computing the SHA-256 hash in-memory during the stream to prevent staging on the ephemeral disk.
- **Storage Paths in R2**:
  - `artifacts/original/{uuid}`
  - `artifacts/sanitized/{uuid}`
  - `reports/scan_report_{uuid}.json`
- **Preserved Properties**:
  - Zero change to the deterministic scanner logic (YARA/ClamAV).
  - SHA-256 verification remains the source of truth for file integrity.
  - Remediation logic (stripping macros/scripts) continues to function identically.

## 4. Workers AI Status
- **Current Integration**: Fully functional in `backend/services/ai_providers/cloudflare_provider.py`.
- **Model**: `@cf/meta/llama-3.1-8b-instruct-fast`
- **Status**: It successfully acts as a fallback provider within the production fallback chain (`ai_fallback_chain`).
- **Action**: Do not modify fallback semantics. Keep as a reliable, free-tier-friendly secondary option.

## 5. Turnstile Status
- **Current Integration**: Fully functional in `backend/utils/turnstile.py`.
- **Security Check**: Verification is strictly **fail-closed** in production environments. If `CLOUDFLARE_TURNSTILE_SECRET_KEY` is missing in production, the system denies all requests.
- **Action**: No modifications required. Behavior is correct and secure.

## 6. Security Implications
- **Credentials**: R2 requires Access Key ID and Secret Access Key. These must be securely passed via environment variables (Render Secrets) and never logged.
- **Data Integrity**: Artifacts moving to R2 will maintain their SHA-256 hashes for cryptographic verification upon retrieval.
- **Turnstile**: Remains fail-closed, ensuring bots cannot bypass the upload endpoint.

## 7. Privacy Implications
- **AI Gateway Logging**: Cloudflare AI Gateway stores logs of prompts and responses. Since Aegis Node processes potentially sensitive uploaded artifacts (e.g., internal CSVs), **we must ensure Cloudflare logs comply with privacy requirements**. We may need to explicitly disable prompt logging in the Cloudflare Dashboard for the Aegis gateway, utilizing only the analytics and rate-limiting features.

## 8. Dependencies
- **AI Gateway**: Requires **zero** new dependencies (re-uses existing `httpx` logic).
- **R2 Storage**: Will require an S3-compatible client. `boto3` (Apache 2.0) is the industry standard and recommended addition. It is a mature, permissive dependency. We will reject adding heavy async orchestration queues (like Celery).

## 9. Cost / Free-Tier Considerations
- **AI Gateway**: Core features (analytics, caching, rate limiting) are completely free. Limits apply to persistent logs (100k free logs), making it highly sustainable.
- **R2**: Free tier includes 10 GB/month and millions of operations, with zero egress fees. Highly sustainable for this project's volume.
- **Workers AI**: Free tier is 10,000 neurons/day. Sustainable as a fallback, but would be easily exhausted if used as the primary provider for heavy analysis.

## 10. Rollback Plan
- **AI Gateway**: If the gateway introduces unacceptable latency or API incompatibilities, simply remove `CLOUDFLARE_AI_GATEWAY_URL` from the environment. `llm_service.py` will gracefully degrade to hitting the provider APIs directly.
- **R2**: If R2 fails, removing the R2 credentials will instruct `file_service.py` to seamlessly fall back to writing to the local ephemeral filesystem.

## 11. Migration Plan
1. Merge the Research Data Freeze (A-F results).
2. Introduce AI Gateway configuration and update LLM providers. Verify telemetry in the Cloudflare Dashboard.
3. Introduce `boto3` dependency.
4. Implement the R2 adapter in `file_service.py`.
5. Deploy to Render with R2 secrets. Verify upload, sanitization, and report generation persist in the bucket.

## 12. What Remains Unchanged
- **Production Architecture**: The FastAPI server on Render remains the core engine.
- **Security Logic**: ClamAV, YARA, Normalization, and Prompt Guard rules remain 100% frozen.
- **Research Results**: The Phase 2 A-F ablation benchmarks remain untouched and authoritative.

## 13. What Must NOT Be Implemented
- **Cloudflare D1**: Do NOT migrate from SQLite. It is an unnecessary database migration that adds zero security value.
- **Cloudflare KV**: Do NOT introduce KV. We do not need distributed state caching at this scale.
- **Cloudflare Queues**: Do NOT introduce. Retain the synchronous/threadpool scanning architecture for simplicity.
- **External Frameworks**: Do NOT install OpenViking, agentmemory, or massive generic API catalogs into the runtime. 
- **Agent Frameworks**: Do NOT convert the core application into a multi-agent framework. Keep it a deterministic pipeline with a single LLM synthesis layer.
