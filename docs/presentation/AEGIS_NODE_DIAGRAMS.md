# Aegis Node Architecture Diagrams

(Note: These are Mermaid representations of the requested diagrams).

## AEGIS_NODE_ARCHITECTURE
```mermaid
graph TD
    Vercel[Vercel: React Frontend] --> Render[Render: FastAPI Backend]
    Render --> Scanner[Deterministic Scanner]
    Render --> TI[Threat Intelligence]
    Render --> AI[AI Guardrails & LLM]
    Render --> Rem[Remediation & Verification]
```

## AEGIS_NODE_PIPELINE
```mermaid
graph LR
    Upload --> Val[Validation]
    Val --> Scan[Static Scan]
    Scan --> Norm[Normalization]
    Norm --> TI[TI Fusion]
    TI --> Guard[AI Guardrail]
    Guard --> LLM[LLM Analysis]
    LLM --> Rem[Remediation]
    Rem --> Ver[Verification]
```

## AEGIS_NODE_TI_FUSION
```mermaid
graph TD
    Indicators --> URLhaus
    Indicators --> AbuseIPDB
    URLhaus --> Fusion
    AbuseIPDB --> Fusion
    LocalScan --> Fusion
    Fusion --> Verdict[Corroborated / Conflicted / Single]
```

## AEGIS_NODE_GUARDRAIL
```mermaid
graph TD
    Dataset --> InputFilter[AI Guardrail]
    InputFilter -- Suspicious Instruction --> RESTRICT[Strip Payload, Keep Metadata]
    InputFilter -- High Confidence --> BLOCK[Bypass LLM]
    InputFilter -- Normal --> ALLOW[Full Context]
```

## AEGIS_NODE_REMEDIATION
```mermaid
graph TD
    Malicious[Malicious Artifact] --> Rem[Remediation Engine]
    Rem --> Sanitized[Sanitized Artifact]
    Sanitized --> Rescan[Mandatory Re-Scan]
    Rescan -- Clean --> Verified[Verified Clean]
    Rescan -- Threat Found --> Failed[Remediation Failed]
```
