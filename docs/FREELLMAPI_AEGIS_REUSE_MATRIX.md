# FreeLLMAPI to Aegis Node Reuse Matrix

| Component | FreeLLMAPI Implementation | Aegis Status / Action | Justification |
| :--- | :--- | :--- | :--- |
| **Error Taxonomy** | Differentiates 429, 500, 401, 404, 408 | **ADAPT** | Improves failover precision and logging inside `llm_service.py`. |
| **Retry-After Parsing** | Reads headers & prose to calculate cooldowns | **ADAPT** | Useful for telemetry and intelligent failure handling. |
| **Provider Fallback Loop** | 20-attempt loop | **REJECT** | Aegis's simple sequential chain is adequate for security scans. |
| **AES-256-GCM DB Encryption** | SQLite Key Storage | **REJECT** | Aegis uses standard env vars/secret files suited for PaaS/Docker. |
| **Model Catalog/Scoring** | Live sync manifest + latency scoring | **REJECT** | Aegis uses a fixed provider configuration. |
| **Tool-Call Rescue** | Regex parsing of plain-text tool use | **REJECT** | Aegis LLMs do not execute tools. |
| **Anthropic / Ollama / MCP** | Multi-protocol translation layer | **REJECT** | No requirement for Aegis to serve external agent traffic. |
| **Context Handoff** | Multi-turn provider transition logic | **REJECT** | Aegis performs single-shot analysis. |
| **Fusion Mode** | Parallel multi-model fanout | **REJECT** | Violates bounded/single-call design constraints. |
