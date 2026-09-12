# Phase 10: UI & Security Observability

## Overview
Phase 10 implements deep security observability into the frontend product, guaranteeing that all defense-in-depth decisions are visible to human operators. 

## Key Principles
1. **Deterministic Authority**: The local scanner is the sole source of truth for the verdict.
2. **AI Security State**: If prompt injection occurs, the UI clearly displays the native Guardrail response (ALLOW, RESTRICT, BLOCK), exact signals fired, and the LLM execution context.
3. **TI Provenance**: Threat intelligence from external providers (URLhaus, AbuseIPDB) is displayed alongside its Fusion corroboration level, strictly isolated from the authoritative deterministic verdict.

## Historical Scans
Scans prior to Phase 9.5B default safely to N/A for guardrails, with no backfilling or fabricated inferences.
