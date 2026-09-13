# AEGIS NODE — PHASE 11: FULL PRODUCT VALIDATION PLAN

## Baseline
- **Frozen release baseline:** `a9aaf02`
- **Current status:** 
  - Phase 9.2 URLhaus = FROZEN
  - Phase 9.3 AbuseIPDB = FROZEN
  - Phase 9.4 TI normalization + fusion = IMPLEMENTED
  - Phase 9.5B native AI guardrails = FROZEN
  - Phase 10 UI + observability = FROZEN
- **Current regression baseline:** 319/319 tests PASS

## Important Directives
- **Phase 11 is VALIDATION ONLY.**
- Do NOT add new features, improve scanners, tune guardrails, add new TI providers, add R2, add new AI frameworks, change A–F research, or redesign the architecture.
- The purpose is to determine whether the current frozen system is operationally and security-wise release-ready.
- The central acceptance philosophy is: **Aegis does not trust any single layer. It validates the interaction between layers and requires verification before accepting a security action.**

---

## A. Test Matrix

Create a full end-to-end matrix covering at minimum:

### CASE 01 — BENIGN DATASET
- **Input:** normal benign CSV/JSON dataset
- **Expected:** upload succeeds, SHA-256 generated, deterministic scan completes, no false malicious classification, TI behaves correctly, guardrail = ALLOW where applicable, LLM analysis is bounded, report generated, UI displays deterministic verdict.

### CASE 02 — KNOWN MALICIOUS ARTIFACT
- **Expected:** deterministic scanner detects threat, local verdict becomes appropriate malicious state, TI enrichment may add evidence, LLM does not override local verdict, remediation only follows existing deterministic policy.

### CASE 03 — SUSPICIOUS DATASET
- **Expected:** suspicious evidence retained, verdict is not incorrectly upgraded to clean, analyst-facing evidence visible.

### CASE 04 — PROMPT INJECTION
- **Expected:** guardrail detects/restricts/blocks according to current rules, dataset content remains untrusted, system/developer instructions remain isolated.

### CASE 05 — HIGH-CONFIDENCE INJECTION
- **Expected:** BLOCK, LLM not invoked where current policy requires blocking, deterministic security verdict unaffected.

### CASE 06 — ENCODED/OBFUSCATED THREAT
- **Test:** bounded encoded content, Unicode obfuscation, normalized representation
- **Expected:** normalization remains bounded, original evidence preserved, no arbitrary execution.

### CASE 07 — URLhaus MATCH
- **Expected:** URL extracted, bounded lookup, normalized evidence, provider provenance visible, URL NEVER fetched, local verdict remains authoritative.

### CASE 08 — AbuseIPDB MATCH
- **Expected:** public IP extracted, non-global/private IPs filtered, bounded lookup, normalized evidence, IP NEVER probed, local verdict remains authoritative.

### CASE 09 — TI CONFLICT
- **Expected:** provider disagreement explicitly visible, CONFLICTED evidence state, no arbitrary provider selected as truth, local deterministic verdict unchanged.

### CASE 10 — TI PROVIDER FAILURE
- **Test:** timeout, 401/403, 429, 5xx, unavailable provider
- **Expected:** local scan remains usable, provider failure becomes limitation, failure is NOT interpreted as benign evidence, failure does NOT overwrite local verdict.

### CASE 11 — LLM FAILURE
- **Test:** timeout, provider unavailable, invalid provider response
- **Expected:** deterministic scan/report remains usable, no fake successful AI result, failure clearly observable.

### CASE 12 — LLM OUTPUT FAILURE
- **Test:** malformed JSON, schema-invalid response, unsupported enum, excessive/invalid fields
- **Expected:** output rejected safely, no action bypass, no verdict mutation, failure observable.

### CASE 13 — REMEDIATION SUCCESS
- **Expected:** remediation runs through deterministic policy, resulting artifact is re-scanned, success is only reported after verification.

### CASE 14 — REMEDIATION FAILURE
- **Expected:** failure clearly reported, no false successful status, verification remains unsuccessful/incomplete.

### CASE 15 — VERIFICATION FAILURE
- **Expected:** remediation cannot be declared successful, verification state remains authoritative.

### CASE 16 — LARGE FILE / UPLOAD LIMIT
- **Expected:** limits enforced, streaming behavior preserved, no memory exhaustion behavior.

### CASE 17 — MALFORMED DATASET
- **Expected:** safe failure, no crash with sensitive stack trace, no execution.

### CASE 18 — FORMULA INJECTION
- **Expected:** only genuinely suspicious formula patterns trigger, benign formulas are not blindly classified as malicious.

### CASE 19 — MALWARE REFERENCE
- **Examples:** WannaCry, LockBit, Mirai, ransomware article/report
- **Expected:** reference ≠ artifact, no automatic malicious verdict solely from the name.

### CASE 20 — ATTACKER URL/IP IN EVIDENCE
- **Expected:** extracted only for bounded TI enrichment, no SSRF, no active probing, no payload retrieval.

---

## B. Security Invariant Matrix

Explicitly validate:

**UPLOAD**
- size limits, file validation, streaming, SHA-256, untrusted storage.

**EXECUTION ISOLATION**
- no execute, no compile, no import/evaluate, no shell execution, no subprocess execution of dataset content.

**NETWORK**
- no dataset-derived URL fetching, no dataset-derived IP probing, fixed provider endpoints only, URLhaus lookup-only, AbuseIPDB lookup-only.

**AI**
- dataset content remains untrusted, system prompt isolation, bounded evidence, guardrail enforcement, schema validation, action policy.

**REMEDIATION**
- deterministic, controlled, post-remediation re-scan mandatory, verification mandatory.

**SECRETS**
- API keys server-side, no secrets in logs, no secrets in API responses, no secrets in frontend.

---

## C. Environment Matrix

Validate:
- **ENVIRONMENT 1:** Local development
- **ENVIRONMENT 2:** Render backend
- **ENVIRONMENT 3:** Vercel frontend
- **ENVIRONMENT 4:** Cloudflare AI Gateway
- **ENVIRONMENT 5:** External TI providers

For each environment record:
- connectivity, authentication, CORS, rate limits, timeout behavior, AI provider routing, TI integration, frontend/backend compatibility.

*IMPORTANT: Cloudflare WAF/proxying must NOT be claimed active unless explicitly verified. AI Gateway and WAF are separate capabilities.*

---

## D. Deployment Validation

Validate:
- Vercel → Render → API → database → scanner → TI → AI Gateway → provider → response → UI
- Test CORS from the deployed Vercel origin.
- Test API authentication.
- Test rate limits.
- Test Turnstile production behavior where applicable.
- Test AI fallback behavior.
- Test provider failures.

---

## E. Data Integrity

Verify:
- SHA-256 remains stable.
- scan records persist correctly.
- analysis records persist correctly.
- guardrail state persists correctly.
- TI evidence persists correctly.
- historical N/A handling works.
- remediation/re-scan/verification state is consistent.

---

## F. Observability Validation

Verify UI and API expose enough information to reconstruct:
- WHAT HAPPENED
- WHY IT HAPPENED
- WHICH LAYER DETECTED IT
- WHICH PROVIDER CONTRIBUTED
- WHETHER LLM WAS USED
- WHETHER REMEDIATION OCCURRED
- WHETHER VERIFICATION SUCCEEDED

*Do not expose secrets or hidden prompts.*

---

## G. Performance Validation

Measure at minimum:
- upload latency
- deterministic scan latency
- TI enrichment latency
- guardrail latency
- LLM latency
- end-to-end latency

*Do not impose arbitrary production SLOs yet. Record measurements for the release baseline.*

---

## H. Failure Injection

Where safely possible, simulate:
- ClamAV unavailable, TI unavailable, TI timeout, LLM timeout, malformed LLM response, database unavailable, invalid API credentials, rate limiting.

*Verify fail-safe behavior. Never simulate failure by modifying production data.*

---

## I. Security Negative Tests

Attempt safe synthetic attacks involving:
- prompt injection, verdict manipulation, remediation manipulation, secret extraction, URL fetching instruction, IP probing instruction, shell execution instruction, system prompt extraction.

*Expected: No unauthorized action.*

---

## J. Acceptance Criteria

Define release-ready only when:

**CRITICAL SECURITY: 100% pass required**
- no dataset execution
- no SSRF through TI
- no secret exposure
- no LLM action bypass
- no remediation verification bypass
- deterministic verdict authority preserved

**FUNCTIONAL: 100% critical workflows pass**
- upload, scan, analysis, TI, remediation, re-scan, verification, UI

**RELIABILITY**
- No unresolved critical/high defects.

**DOCUMENTATION**
- All known limitations recorded.

**DEPLOYMENT**
- Local and deployed paths behave consistently within documented limitations.

---

## K. Failure Classification

Classify every failure as:
- **P0 Critical:** Security boundary bypass / data compromise / arbitrary execution
- **P1 High:** Core security or workflow failure
- **P2 Medium:** Functional degradation with safe fallback
- **P3 Low:** UI/usability/documentation issue

*Only P0/P1 must block release automatically.*

---

## L. Evidence Collection

Create:
`experiments/phase11/`

Store:
- validation results, JSON/CSV summaries, sanitized logs, latency measurements, deployment checks, screenshots where useful, failure cases.

Do not store:
- API keys, credentials, sensitive user data, raw secrets, uncontrolled malware payloads.

---

## M. Reports

Create:
`docs/PHASE_11_VALIDATION_REPORT.md` (upon execution)

Include:
- environment matrix, test matrix, functional results, security results, failure injection, performance, deployment validation, UI validation, known limitations, unresolved findings, release recommendation.

---

## N. Defect Handling (NO FEATURE CHANGES)

If a test reveals a problem:
- DO NOT automatically fix it in Phase 11.
- First classify it.
- Only make a code change when security requires immediate containment OR the defect makes validation impossible. Document all such changes separately.
- Otherwise: record defect, continue validation, prepare remediation for a separate fix phase.

---

## O. Final Release Decision

At the end produce exactly one:
- **RELEASE READY**
- **RELEASE BLOCKED**
- **RELEASE READY WITH DOCUMENTED LIMITATIONS**

*Use evidence, not intuition.*
