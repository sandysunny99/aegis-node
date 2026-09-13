# Aegis Node: Known Limitations

1. **AI Guardrail Holdout Metrics**
   - The native prompt-injection guardrail is evaluated at:
     - 100% detection / 0% FPR on development benchmarks.
     - 80% detection / 20% FPR on independent holdout sets.
   - These are controlled benchmark limitations and do not guarantee evasion-proof protection in the wild.

2. **Binary Remediation Limitation**
   - Remediation strictly applies to structured data (CSV, JSON, TXT). Arbitrary binary uploads are safely blocked at the `/upload` endpoint, rendering remediation for arbitrary binaries unsupported.

3. **Threat Intelligence Coverage**
   - TI is bounded to URLhaus and AbuseIPDB. It relies on provider availability and rate limits. Outages result in graceful fallback to local deterministic scans.

4. **LLM Provider Dependency**
   - Analytical features depend on upstream provider availability (e.g., Gemini, Cloudflare AI). System functionality gracefully degrades to deterministic scans if APIs are unreachable.

5. **Static Analysis Only**
   - Aegis Node performs static analysis. There is **no dynamic sandboxing** or detonation of malicious artifacts.

6. **Render Ephemeral Storage**
   - The free tier of Render utilizes ephemeral `/tmp` storage. Databases and uploaded files are lost upon application restarts.
