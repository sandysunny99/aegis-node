# Security Comparison: FreeLLMAPI vs Aegis Node

## 1. Threat Models
- **FreeLLMAPI:** Protects the *user's API keys* from local exposure and protects *vendor accounts* from being banned due to extreme request volumes.
- **Aegis Node:** Protects the *application and user environment* from malicious code, malware, and adversarial prompt injections present in scanned datasets.

## 2. Key Storage
- **FreeLLMAPI:** Uses `AES-256-GCM` encryption within a local SQLite database (`crypto.ts`). Keys are decrypted only at the exact moment of HTTP dispatch. 
- **Aegis Node:** Relies on environment variables and Render/Docker secret files. In a production SaaS architecture, this is standard and sufficient.

## 3. Data Sanitization & Guardrails
- **FreeLLMAPI:** Zero semantic content filtering. Prompts pass through raw to preserve coding agent intent.
- **Aegis Node:** Implements extreme data minimization (max 15 findings), semantic injection detection (`services.guardrails.evaluate_input_guardrail`), HTML stripping, output field truncation, and high-risk verb flagging. 

## 4. Architectural Authority
- **FreeLLMAPI:** The LLM is the core engine; its output is the primary product.
- **Aegis Node:** The LLM is advisory context downstream of deterministic scanners (ClamAV, YARA). If the LLM goes rogue or is bypassed, the system degrades securely to deterministic remediation logic.

## 5. Conclusion
Aegis Node possesses a fundamentally stronger, defense-in-depth application security model than FreeLLMAPI. No FreeLLMAPI security components need to be imported into Aegis.
