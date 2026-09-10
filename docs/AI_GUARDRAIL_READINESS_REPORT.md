# AI Guardrail Readiness Report

## 1. Current Guardrails
Aegis Node currently relies predominantly on architectural isolation and strict deterministic validation rather than semantic AI-driven guardrails:
- **Input Isolation:** Raw cell data is stripped entirely from the `_build_compact_evidence` payload, feeding only metadata (like `rule_id` and truncated `location`).
- **Prompt Tagging:** Evidence is explicitly scoped within `<UNTRUSTED_DATA>` XML-style tags.
- **Strict Output Validation:** Pydantic models force enum conformity (`verdict`, `severity`) and type safety on all LLM responses.
- **Output Sanitization:** `_sanitize_llm_output` truncates strings, strips HTML, drops control chars, and caps lists.
- **Deterministic Regex Blocks:** `_DANGEROUS_PATTERNS` regex strictly rejects outputs that reflect commands like `rm -rf` or `ignore previous instructions`.
- **Architectural Security:** The LLM does not execute code, call tools, resolve domains, or alter the authoritative verdict of the ClamAV+YARA scanner. It is solely an interpretation layer.

## 2. Missing Controls
While architectural guardrails are extremely robust, the semantic layer has gaps:
- **Input Scanning:** We lack static checks for obfuscated prompt injections (e.g., Base64-encoded instructions hidden inside a `location` field or a filename).
- **Prompt Impersonation / System Leakage:** Advanced jailbreaks (e.g., "Developer Instruction: ...") are not blocked by the output regex if they manipulate the model into generating a seemingly valid JSON response without explicitly printing a blocked string.
- **Hallucination Checks:** There is no entailment check to ensure the LLM's `evidence` array actually correlates with the deterministic `findings` array provided to it.
- **Toxicity / Secrets:** No input/output scanning for API keys or PII, which could be leaked if an analyst inadvertently embedded them in dataset metadata.

## 3. Prompt-Injection Assessment
**Status: PARTIAL.**
Local testing with synthetic prompt-injections (Cases 1-12 in `tests/test_security.py`) proved that:
- Direct commands (`ignore previous instructions`, `rm -rf`) are aggressively blocked by our custom regex.
- Embedded payloads inside valid JSON or CSV strings are similarly caught if they reflect the blocked phrases.
- **However**, encoded injections (Base64), impersonation ("System: You are now a friendly assistant"), and authority-claiming instructions bypass the rigid regex entirely.
- Despite this, the LLM remains physically incapable of executing the injections. The risk is strictly limited to dataset misclassification in the LLM's advisory summary.

## 4. Output-Security Assessment
**Status: PASS.**
The custom stack-based JSON extractor (`_extract_first_json_object`) combined with strict Pydantic validation successfully prevents the LLM from outputting arbitrary fields, altering the scanner configuration, or overflowing the buffer. The schema is highly defensive and fails closed (returns AI unavailable).

## 5. Action-Security Assessment
**Status: PASS.**
This is Aegis Node's strongest area. The local deterministic scanner explicitly maintains the final authority. Remediation logic executes deterministically on the local file. The LLM cannot invoke tools, alter the filesystem, or interact with external services. Even if the LLM is fully compromised to return `verdict: clean`, the deterministic scanner's `malicious` verdict will override it.

## 6. Open-Source Comparison

| Library | Purpose | Deployment Complexity | Input/Output Scanning | Gateway Features | Recommended? |
|---|---|---|---|---|---|
| **LLM Guard** | Narrow input/output security scanning (injection, secrets, PII, toxicity) | Low (Python library, local inference) | Strong semantic scanning (many pre-trained ONNX models) | None | **YES** |
| **NVIDIA NeMo** | Programmable guardrails, dialog flows, tool security | High (Large framework, complex policy language) | Yes (via dialog rails) | None | NO (Overkill for our non-interactive LLM use case) |
| **Guardrails AI** | Structured validation and schema enforcement | Medium (Transitioning to self-hosted hub) | Yes (via validators) | None | NO (Duplicates our existing Pydantic schema validation) |
| **LiteLLM** | LLM Gateway / Router | Low to Medium | Basic | Strong (Rate limits, fallbacks, observability) | NO (We already use Cloudflare AI Gateway for this) |

## 7. Recommended Architecture
**OPTION B:** Integrate LLM Guard as a narrow input/output security layer.

The final LLM path will be:
```
AEGIS NODE
    │
    ├─ Native Security Guardrails (Pydantic, Regex, File Scanning)
    │
    ↓
Evidence Builder
    ↓
LLM Guard (Input Scan: Prompt Injection, Obfuscation)
    ↓
Cloudflare AI Gateway (Routing, Observability, Rate Limits)
    ↓
LLM Provider (Gemini / Llama / Groq)
    ↓
LLM Guard (Output Scan: Toxicity, Secrets Leakage, Entailment)
    ↓
Native Output Guard (Pydantic Schema Validation)
    ↓
Deterministic Remediation (Authoritative)
```

## 8. Dependency/Complexity Impact
LLM Guard will introduce additional Python dependencies (primarily Transformers/ONNX for local models). This is acceptable as it runs within our existing FastAPI backend and doesn't require a separate standalone service. Cloudflare AI Gateway introduces zero dependency overhead, as it is just an API URL replacement.

## 9. Benchmark Plan
Before deploying LLM Guard to production, we must benchmark its impact on:
- **Latency Overhead:** Measure the added ms per scan.
- **False Positives:** Ensure legitimate cybersecurity terms (e.g., "malware", "exploit", "shellcode") embedded in benign dataset evidence are not incorrectly blocked by toxicity/injection scanners.
- **Attack Detection Rate:** Verify it catches the Base64 and impersonation bypasses identified in Section 3.

## 10. Decision
We will proceed with **OPTION B**. The Aegis native security controls and Cloudflare AI Gateway remain our primary operational boundaries. LLM Guard will be implemented strictly as a semantic safety net (input/output scanning) to cover the gaps in our rigid regex-based prompt injection defenses.
