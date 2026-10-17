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

## Remote ClamAV on the owner's Oracle VM (added October 2026)

- On Render, ClamAV runs on a separate Oracle Cloud VM owned by the project author. Each uploaded file is sent over HTTPS, with a bearer token, to that VM for scanning. It is not sent to any third party, and the gateway does not keep it after the scan.
- If the VM is unreachable, rejects the token or is busy, the scan says `CLAMAV_UNAVAILABLE` and can be at best "Clean, with limitations". Aegis never substitutes a mock scanner or another service.
- ClamAV's EICAR signature only matches at the start of a file. EICAR embedded in a CSV cell is caught by Aegis' YARA and raw-byte rules, not by ClamAV.
- Oracle may reclaim an idle Always Free VM (official rule: 7 days below 20 % CPU, network and memory). Scans then report ClamAV as unavailable until the VM is recreated.
- Render free tier: 512 MB memory (lite uploads capped at 25 MB, from measurement), sleeps when idle, and has no persistent disk unless R2 and an external database are configured. `/health/detectors` reports whether storage and the database persist.
