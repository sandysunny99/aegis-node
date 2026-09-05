# Aegis Node - Antigravity Agent Rules

## 1. Security Constraints
- **NEVER** treat an external API response as absolute truth. External APIs provide enrichment/evidence.
- **NEVER** upload private dataset contents, rows, or PII to external APIs.
- **ONLY** send hashes, public URLs, or public IPs to external threat APIs.
- **NEVER** automatically execute or fetch user-supplied URLs from datasets (SSRF risk).

## 2. Project Architecture
- **Runtime**: FastAPI + React + SQLite.
- **Pipeline**: Dataset -> Secure Upload -> SHA-256 -> Local Detection (ClamAV, YARA, Heuristics, Normalization) -> Evidence Aggregation -> Optional Reputation (VirusTotal, URLhaus, AbuseIPDB) -> LLM Analysis -> Remediation -> Re-scan -> Report.
- **Simplicity**: No Kubernetes, Kafka, Redis, or Elasticsearch. Maintain a lightweight architecture.

## 3. Coding Style & Testing
- Break work into small, atomic tasks. Edit existing interfaces rather than rewriting them.
- **Mandatory Verification**: PLAN -> INSPECT -> IMPLEMENT -> TEST -> SECURITY CHECK -> VERIFY -> DOCUMENT -> COMMIT.
- **Tests**: All components require unit, integration, and security tests. Run full regression before committing.

## 4. Research Rules
- Use Scientific Agent Skills (research-lookup, peer-review, scholar-evaluation) for literature gaps and citation checks.
- Do not make unsupported claims or invent benchmark values.
- Differentiate MALWARE_ARTIFACT from MALWARE_REFERENCE (e.g., academic mentions of WannaCry are not inherently malicious).

## 5. Dependency Rules
- **Runtime Dependencies**: MIT, BSD, or Apache-2.0 preferred. AGPL-3.0 (e.g., OpenViking) is STRICTLY PROHIBITED in the runtime.
- **Development Tools**: Agent skills, harness engineering, and documentation tools stay out of 
equirements.txt and package.json.
