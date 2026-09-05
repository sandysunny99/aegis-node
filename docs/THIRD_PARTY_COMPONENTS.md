# Third-Party Components & Attribution Registry

**Project**: Aegis Node  
**License Compliance**: Open-Source Attribution & Provenance Tracking  

---

## 1. Adopted Third-Party Libraries & Datasets

### A. YARA Engine
* **Component**: `yara-python`
* **Repository**: [https://github.com/VirusTotal/yara-python](https://github.com/VirusTotal/yara-python)
* **License**: BSD-3-Clause
* **Copyright**: (c) 2013-2024 VirusTotal
* **Purpose**: Local Stage 1.5 compiled binary and regex pattern matching for dataset malware vectors.
* **Integration Method**: Standard Python package via `pip install yara-python`.

### B. VirusTotal API v3 Client
* **Component**: `backend/services/integrations/virustotal_client.py`
* **Service Reference**: [https://developers.virustotal.com/reference/overview](https://developers.virustotal.com/reference/overview)
* **Purpose**: Privacy-preserving SHA-256 cryptographic hash reputation lookup across 70+ antivirus engines.
* **Integration Method**: In-house asynchronous HTTP adapter using standard `httpx`.

### C. Prompt Injection Evaluation Benchmark Dataset
* **Component**: `tests/fixtures/prompt_injection_benchmark/`
* **Source**: [https://github.com/mirzaakhi/prompt-injection-detection-dataset](https://github.com/mirzaakhi/prompt-injection-detection-dataset)
* **License**: MIT / CC-BY-4.0
* **Author**: Mirzaakhi et al.
* **Purpose**: Held-out empirical evaluation benchmark for testing detector resilience against unseen attack types and benign hard negatives.

---

## 2. Adapted Techniques & Conceptual Attributions

### A. Multi-Encoding Normalization
* **Inspiration**: Prompt Shield ([https://github.com/mthamil107/prompt-shield](https://github.com/mthamil107/prompt-shield))
* **License**: MIT
* **Adaptation**: Native recursive deobfuscation (Base64, Hex, URL, Unicode, Rot13) implemented in `scanner/heuristics.py`.

### B. Multi-Signal Score Fusion
* **Inspiration**: Prompt Armor ([https://github.com/prompt-armor/prompt-armor](https://github.com/prompt-armor/prompt-armor))
* **License**: MIT
* **Adaptation**: Transparent weighted evidence aggregation formula combining local heuristics, YARA signatures, ClamAV status, and CTI reputation.

### C. Multi-Engine Pipeline & Result Model
* **Inspiration**: Revisor ([https://github.com/a-sarja/Revisor](https://github.com/a-sarja/Revisor))
* **License**: MIT
* **Adaptation**: Normalized Pydantic engine result schema (`EngineDetectionResult`) without Celery/Redis queue dependencies.
