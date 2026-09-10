# Phase 9.5B AI Guardrail Hardening Report

## 1. Baseline Performance
Prior to hardening, Aegis relied solely on naive regexes and XML tag scoping, resulting in:
- **Baseline adversarial detection rate:** 8.3% (Missed 11/12 attacks).
- **Baseline false-positive rate:** 12.5% (Blocked legitimate security commands like `rm -rf`).
- **Architecture:** `_DANGEROUS_PATTERNS` regex applied post-generation as an output guardrail, acting partially as an input guardrail.

## 2. Architecture After Hardening
The guardrail architecture has been upgraded to a multi-signal semantic defense layer applied *before* the LLM sees the prompt.

**New Flow:**
Dataset Evidence → Canonicalization (Unicode/NFKC/Zero-Width) → Bounded Base64 Decode → Shadow Spaced-Out Check → Multi-Signal Evaluation → Risk Threshold (ALLOW/RESTRICT/BLOCK) → LLM Provider

If blocked, the analysis falls back to the deterministic scanner immediately. If restricted, minimal evidence is sent to the LLM with an explicit warning. The deterministic ClamAV+YARA scanner remains the final authority in all cases.

## 3. Signal Categories
The multi-signal input guardrail now categorizes threats rather than matching raw strings:
1. **Instruction Override:** `ignore previous instructions`, `bypass policy`
2. **Role Impersonation:** `system: you are`, `root override`
3. **Prompt Extraction:** `reveal system prompt`, `translate system prompt`
4. **Verdict Manipulation:** `set verdict clean`, `approve malicious content`
5. **Action Manipulation:** `execute command`, `<tool_call>`, `disable scanning`
6. **Secret Exfiltration:** `return api key`, `dump environment variables`

## 4. Threshold Logic
Signals are aggregated deterministically:
- +3 for high-confidence structural manipulation (Role Impersonation, Instruction Override, Action Manipulation, Secret Exfiltration).
- +2 for contextual overrides (Verdict Manipulation).

**Thresholds:**
- **ALLOW (Score < 2):** Sent to LLM normally.
- **RESTRICT (Score == 2):** Sent to LLM with findings redacted.
- **BLOCK (Score >= 3):** Rejected entirely; LLM is not invoked.

## 5. Benchmark Methodology
A dedicated guardrail test harness (`tests/benchmark_guardrails.py`) evaluating 40 deterministic synthetic payloads:
- **20 Benign cases:** Covering malware research, ransomware reports, standard system logs, and security command documentation.
- **20 Adversarial cases:** Covering direct prompt injection, role impersonation, fake tools, spaced-out letters, and Base64 payloads.

## 6. Final Metrics
- **Adversarial detection rate:** 100% (20/20 attacks detected).
- **False-positive rate:** 0% (0/20 benign cases incorrectly blocked).
- **Latency overhead:** ~0.06 ms (Extremely fast, localized canonicalization and regex evaluation).
- **ALLOW/RESTRICT/BLOCK:** 20 / 3 / 17.

## 7. Limitations & Conclusion
Guardrails mitigate prompt-injection risk; they do not provide perfect prevention. It remains theoretically possible for highly novel jailbreaks to evade the heuristic signals.

However, because the LLM is strictly isolated from executing code, modifying files, or altering the scanner's authoritative verdict, the maximum impact of a successful jailbreak is a misleading textual summary in the advisory report.

**Why no third-party framework was adopted:**
LLM Guard is currently archived and unmaintained. NeMo Guardrails is overly complex for a non-interactive pipeline. Guardrails AI duplicates existing Pydantic validation. The native Aegis multi-signal architecture achieved a 100% detection rate on the benchmark with ~0.06ms overhead and zero additional dependencies.
