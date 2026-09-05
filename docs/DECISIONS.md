# Architectural Decisions
- **ADR-001**: Use FastAPI and SQLite for a lightweight, deployable runtime.
- **ADR-002**: Local Detection First. ClamAV and YARA provide ground truth; LLM provides context, not primary detection.
- **ADR-003**: No AGPL dependencies in runtime. OpenViking ideas used for context only.
- **ADR-004**: Render Free Tier compatibility requires ephemeral SQLite (/tmp) instead of persistent disks.
