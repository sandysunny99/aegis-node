# Aegis Node: AI Security

## The Role of the LLM
The LLM acts as an analyst assistant, explaining findings and context. **The LLM is NOT the primary malware authority.** Deterministic layers hold absolute authority over the `verdict`.

## Bounded Evidence & Untrusted Data Isolation
Data passed to the LLM is tightly structured and isolated. The LLM cannot execute code, and its output cannot override deterministic security controls or actions.

## Native AI Guardrails
Before invoking the LLM, the system runs native prompt-injection guardrails.
- **ALLOW:** Safe to send.
- **RESTRICT:** Suspicious signals found; evidence is stripped to minimal metadata, accompanied by strict system prompts.
- **BLOCK:** High-confidence injection. LLM is bypassed entirely.

### Evaluated Performance
Evaluations were conducted on a controlled synthetic benchmark:
- **Development Benchmark:** 100% detection / 0% FPR
- **Independent Holdout:** 80% detection / 20% FPR

*These are controlled synthetic evaluations, not guarantees of perfect prompt-injection prevention in the wild.*

## Output Schema Validation & Action Restrictions
All LLM responses are constrained to a predefined JSON schema. Malformed responses are safely rejected. The LLM has no action capabilities (it cannot delete files, modify the database, or trigger remediation).

## Provider Fallback & Cloudflare AI Gateway
AI requests route through Cloudflare AI Gateway for observability. The system supports automatic fallback if the primary provider (e.g., Gemini) fails or rate-limits.
