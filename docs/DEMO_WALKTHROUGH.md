# Aegis Node: Live Demo Walkthrough Script
**Target Duration:** 5–7 minutes
**Audience:** Thesis Evaluation Panel

---

## 1. Introduction (0:00 - 1:00)
**Presenter:** "Welcome to the demonstration of Aegis Node. Aegis Node is a zero-trust, edge-first data processing gateway designed to detect and remediate sophisticated threats—such as prompt injection, command execution, and malicious formulas—before they can enter internal environments. The key architectural principle here is **Deterministic-First Security**. The LLM is used *only* for contextual analysis, never for primary security enforcement."

## 2. File Upload & Primary Scan (1:00 - 2:00)
**Action:** Upload the `G01_mixed_content.csv` file from the synthetic benchmark dataset.
**Presenter:** "I am uploading a mixed-content dataset. Once the file hits the gateway, Aegis bypasses traditional file-extension assumptions and begins a deterministic scan."

**Action:** Show the scanner logs or UI flagging the file.
**Presenter:** "Notice what happens instantly:
- The **ClamAV Engine** scans the binary stream.
- The **YARA Engine** looks for static malware signatures.
- Most importantly, the **Heuristic Engine** detects embedded prompt injections (e.g., 'Ignore all prior instructions') and DDE formula injections (e.g., `=CMD(|'/C calc.exe')`)."

## 3. The LLM Contextual Analysis & Provider Resilience (2:00 - 3:30)
**Action:** Point to the 'AI Analysis' phase in the UI.
**Presenter:** "Once the deterministic engines flag the file, we invoke an LLM to generate a human-readable threat context summary. However, we do not send the raw file. We send only a compact, neutralized JSON metadata object."

**Action (Optional):** If possible, trigger an artificial rate limit (or simply explain the fallback).
**Presenter:** "In production, relying on a single AI provider is a critical point of failure. If our primary provider (Groq) is rate-limited or unavailable, the system does not crash or block. It triggers our **Provider Resilience Chain**."
* "The request immediately cascades down to NVIDIA NIM."
* "If NVIDIA is unavailable, it routes to Cloudflare Workers AI."
* "This ensures that the security pipeline maintains 100% uptime without blocking the scan thread on `Retry-After` headers."

## 4. Verdict & Remediation (3:30 - 5:00)
**Action:** Show the final verdict screen displaying "SUSPICIOUS" or "MALICIOUS".
**Presenter:** "The final verdict is derived strictly from the deterministic engine. The LLM merely provides the summary."

**Action:** Click the "Remediate" or "Sanitize" button.
**Presenter:** "Because the file was flagged, the user cannot download the raw file. Instead, we initiate Remediation. Aegis applies format-preserving neutralization—stripping executable macros, nullifying DDE formulas by prepending single quotes (`'=CMD(...)`), and defanging prompt injection strings, all while keeping the benign data intact."

## 5. Re-Scan & Verification (5:00 - 6:00)
**Action:** The system automatically re-scans the sanitized file.
**Presenter:** "A core principle of Aegis Node is that remediation is never blindly trusted. The sanitized file is immediately fed back through the exact same deterministic scanning pipeline."

**Action:** Show the successful 'CLEAN' output and the generated download link.
**Presenter:** "The re-scan confirms that all actionable threats have been neutralized. The system issues a time-bound, single-use download token. The researcher can now safely download the benign data without compromising their local environment."

## 6. Conclusion (6:00 - 7:00)
**Presenter:** "To summarize: Aegis Node proves that we can secure data ingestion against modern AI-era threats by combining strict deterministic rule-sets with highly resilient, multi-provider contextual LLM analysis. This concludes the demo."
