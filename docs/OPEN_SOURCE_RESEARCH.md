# Aegis Node — Open-Source Research & Architectural Assessment

**Document Type**: Comprehensive Research Report  
**Author**: Senior AI Security Architect & M.Tech Research Project Reviewer  
**Status**: Research & Architecture Assessment Complete  

---

## 1. Executive Summary

This research investigates open-source repositories, detection engines, security libraries, threat intelligence APIs, and evaluation datasets to elevate Aegis Node's detection accuracy, threat coverage, and academic rigor without introducing architectural bloat or violating deployment constraints.

---

## 2. Research Findings by Domain

### A. Malware & Binary Scanning
* **Current State**: Aegis Node utilizes raw binary prefix checks (Stage 0) and a ClamAV TCP client (Stage 1).
* **Research Recommendation**:
  * **Adopt YARA Engine (`yara-python`)**: Introduce Stage 1.5 scanning with a curated ruleset targeting embedded Windows PEs, shellcode NOP sleds, webshell execution stagers, and EICAR strings.
  * **Maintain ClamAV Architecture**: Preserve the lightweight non-blocking TCP socket client with simulated mock fallback.

### B. Threat Intelligence & Reputation
* **Current State**: Purely local offline scanning.
* **Research Recommendation**:
  * **Adopt VirusTotal API v3 (Hash-First)**: Implement an asynchronous SHA-256 hash lookup client (`lookup_file_hash`).
  * **Privacy Guarantee**: Never upload full dataset files; query only cryptographic hashes.
  * **Fail-Safe**: If unconfigured or rate-limited, local scanning operates at 100% capacity with zero latency degradation.

### C. Prompt Injection & Obfuscation Defense
* **Current State**: Regex keywords + LLM `<UNTRUSTED_DATA>` XML tag isolation.
* **Analysis of Vigil, Prompt Armor, and Prompt Shield**:
  * Vigil proves that modular scanning separates concerns effectively, but its heavy DeBERTa/PyTorch stack is unsuitable for lightweight container deployments.
  * Prompt Armor’s multi-signal fusion and Prompt Shield’s multi-encoding decoders (Base64, Hex, URL, Unicode homoglyphs, Rot13) provide maximum defense against adversarial evasion with sub-millisecond execution.
* **Research Recommendation**:
  * **Adapt Multi-Encoding Normalization**: Integrate recursive Base64/Hex/URL/Unicode deobfuscation into Stage 0.5 heuristics before regex matching.
  * **Benchmark with Public Dataset**: Evaluate detector robustness against `mirzaakhi/prompt-injection-detection-dataset`.

---

## 3. Comprehensive Component Evaluation Table

| Component | Current Aegis Implementation | Candidate OSS / Reference | Advantage of Candidate | Technical / Complexity Risk | License | Final Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Antivirus Scanner** | Non-blocking TCP client to `clamd` | ClamAV Daemon + Mock | Proven standard signatures | Daemon memory footprint (1.2 GB) | GPL-2.0 | **MAINTAIN (Current)** |
| **Pattern Matching** | Hardcoded regex in `engine.py` | `yara-python` | Standardized rule language; fast C execution | Requires OS C-library bindings | BSD-3 | **ADOPT (Stage 1.5)** |
| **Threat Intelligence** | None (100% local) | VirusTotal API v3 | Verifies 70+ global AV verdicts | 4 req/min rate limit; network dependency | Proprietary / Free Tier | **ADOPT (Hash-First)** |
| **Pipeline Architecture** | Sequential synchronous pipeline | Revisor multi-engine model | Standardized multi-engine output schema | Distributed Celery/Redis queue bloat | MIT | **ADAPT (Adapter Schema Only)** |
| **Prompt Injection Scanner** | Keyword regex in `content_checker.py` | Vigil / Prompt Armor / Prompt Shield | Multi-layer decoding, normalization, and score fusion | Large ML models exceed RAM limits | Apache-2.0 / MIT | **ADAPT (Technique Only)** |
| **Evaluation Dataset** | In-house 60-sample synthetic set | `mirzaakhi/prompt-injection-detection-dataset` | Held-out attack types; hard negative evaluation | Dataset formatting differences | MIT / CC-BY-4.0 | **ADOPT (Benchmark Only)** |

---

## 4. Architectural Decisions Summary

### 1. ADOPT:
* `yara-python` (BSD-3-Clause): Stage 1.5 curated dataset rule engine.
* `virustotal-api-v3` client (Custom lightweight HTTP adapter): Hash-first reputation lookup.
* `mirzaakhi/prompt-injection-detection-dataset`: Evaluation benchmark dataset with hard negatives.

### 2. ADAPT:
* **Multi-Encoding Normalization Pipeline** (from Prompt Shield / Prompt Armor): Deobfuscates nested Base64, Hex, URL-encoding, and homoglyphs.
* **Multi-Engine Evidence Aggregator** (from Revisor): Standardized engine detection result schema.
* **Transparent Multi-Signal Score Fusion** (from Prompt Armor): Weighted combination of heuristic entropy, YARA, ClamAV, and CTI signals.

### 3. REFERENCE ONLY:
* `deadbits/vigil-llm`: Modular scanner architecture reference.
* `Neo23x0/signature-base`: Pattern reference for high-precision YARA rules.
* `elastic/protections-artifacts`: Cloud dropper detection reference.

### 4. DEFER:
* **AbuseIPDB / AlienVault OTX**: Secondary CTI lookups deferred to preserve simplicity and avoid multi-key configuration friction.
* **Local In-Memory Vector Embeddings**: Deferred until empirical benchmarks prove necessity beyond recursive normalization.

### 5. REJECT:
* **Celery / Redis / Kafka** (Revisor distributed queues): Unnecessary infrastructure for an M.Tech project.
* **PyTorch / HuggingFace DeBERTa / Transformers** (Vigil ML stack): Heavy dependencies (> 1.5 GB RAM) that crash Render free tiers.
* **Protect AI Rebuff**: Rejected due to maintainer archival and external vector DB lock-in.
* **Automated File Upload to Third Parties**: Rejected to protect dataset privacy and data integrity.
