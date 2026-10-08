# Aegis Node Local E2E Validation

## Environment
- OS: Windows
- Python version: 3.12.x
- Node version: 20.x+
- Docker status: UNAVAILABLE
- current commit: 8b16c4c

## Phase Results

| Phase | Status | Evidence | Limitation |
|------|------|------|------|
| Git Freeze | PASS | Verified `main` @ `8b16c4c` | None |
| Architecture | PASS | Compose and backend configurations validated | None |
| Real ClamAV | BLOCKED/PENDING | Docker unavailable | Real daemon not tested |
| Upload | PASS | Synthetic CSV successfully uploaded and parsed | None |
| Scan | PASS | Mock offline ClamAV correctly returns `clean_with_limitations` | Real ClamAV pending |
| YARA | PASS | YARA signatures triggered on obfuscated scripts | None |
| Normalization | PASS | Encoded payload successfully deobfuscated and flagged | None |
| Guardrail | PASS | LLM guardrail logic triggered during analysis | None |
| Threat Intel | PASS | URLHaus/VT mocks integrated | None |
| Groq | PASS | `openai/gpt-oss-20b` executed without errors | None |
| Groq→NVIDIA | PASS | Fallback chain activated successfully on mocked Groq failure | None |
| Remediation | PARTIAL | API reached correctly; clean datasets skipped as expected. Row-level sanitization needs EICAR/malware testing with active ClamAV | Full effectiveness pending real ClamAV |
| Verification | PASS | Limits appropriately enforced on offline scanners | None |
| Security | PASS | `.exe` and python script uploads correctly rejected (415). Unauthenticated endpoint rejected with 403 (Turnstile). | None |
| Frontend | PASS | `npm run build` completed cleanly without errors | Browser e2e pending |

## Important distinction

**LIVE PRODUCTION VERIFIED:**
- Render deployment
- frontend reachability
- `/health`
- production environment configuration

**LOCAL VERIFIED WITHOUT REAL CLAMAV:**
- upload
- deterministic scanning paths
- AI
- fallback
- TI
- guardrails
- remediation logic where applicable
- security tests
- local configuration defaults (docker-compose synced)

**PENDING:**
- real ClamAV daemon integration
- browser-based live Turnstile token + live upload
- live Render remediation on finding-bearing fixture
