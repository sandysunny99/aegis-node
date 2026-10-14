# FreeLLMAPI Repository Inventory

## 1. Overview
Target: `tashfeenahmed/freellmapi`
Type: npm workspaces monorepo (TypeScript)
Purpose: Aggregate free-tier LLM API allocations behind a single OpenAI-compatible `/v1` endpoint.

## 2. Structural Breakdown

### `server/` (Core Proxy Engine)
Node.js + Express + better-sqlite3.
- `src/app.ts`, `index.ts`: Application bootstrap and express routing.
- `src/routes/`: Inbound HTTP handlers (`proxy.ts`, `anthropic.ts`, `ollama.ts`, `mcp.ts`).
- `src/services/`: Core logic (`router.ts`, `ratelimit.ts`, `health.ts`, `fusion.ts`).
- `src/lib/`: Utilities (`crypto.ts` for AES-256-GCM, `fallback-loop.ts`, `tool-call-rescue.ts`).
- `src/providers/`: Abstract `base.ts`, registry `index.ts`, and adapters like `openai-compat.ts`.
- `src/db/`: SQLite initialization and file-per-migration strategy.

### `client/` (Web Dashboard)
React 18 + Vite SPA for managing keys, observing analytics, and editing the model fallback chain.

### `desktop/` (Native Wrapper)
Electron-based desktop application providing a menubar tray interface and automatic startup.

### `cli/` (Command Line Tools)
CLI commands for quickly configuring coding agents (e.g., `setup-claude`, `launch-codex`).

### `shared/` (Common Contracts)
Typescript definitions (e.g., `Provider`, `Model`, `ChatCompletion`) shared across server and client workspaces.

## 3. Data Storage
Relies on a single, local SQLite database for encrypted key storage, provider tracking, request logging, and model capability caching.
