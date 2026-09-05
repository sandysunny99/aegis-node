# Open-Source Component Evaluation & Decision Matrix

**Evaluation Criteria**:
1. License Compatibility (Permissive vs Copyleft)
2. Accuracy & False-Positive Behavior
3. Performance & Resource Footprint (< 512 MB RAM for Render deployment)
4. Dependency Weight & Security Vulnerability Profile
5. Ease of Integration Behind Clean Adapters

---

## 1. Decision Matrix

| Candidate Component | Primary Function | License | Accuracy Potential | Performance / Latency | Dependency Weight | Security Risk | Integration Complexity | Final Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`yara-python`** | Binary/text pattern scanning | BSD-3-Clause | Very High | < 1 ms per cell | Lightweight C-extension | Low | Low (Thin adapter) | **ADOPT** |
| **VirusTotal v3 (Hash Lookup)** | Global multi-engine AV reputation | Proprietary (Free API) | Maximum | 100–300 ms (Async) | Zero (uses existing `httpx`) | Zero (Hash-only) | Low (Async client) | **ADOPT** |
| **`mirzaakhi` Benchmark Dataset** | Held-out attack evaluation | MIT / CC-BY-4.0 | N/A (Test set) | N/A | Zero | Zero | Zero (Fixture only) | **ADOPT** |
| **Prompt Shield Decoders** | Recursive encoding normalization | MIT | High | < 2 ms | Zero (Pure Python) | Low | Low (Stage 0.5 helper) | **ADAPT** |
| **Prompt Armor Score Fusion** | Multi-signal risk calculation | MIT | High | < 0.1 ms | Zero (Pure Python math) | Low | Low (Scoring function) | **ADAPT** |
| **Revisor Result Schema** | Multi-engine standardized records | MIT | High | Zero | Zero (Pydantic model) | Low | Low (Model schema) | **ADAPT** |
| **Vigil DeBERTa / Transformers** | ML prompt injection classifier | Apache-2.0 | High | 1500–2500 ms | Heavy (> 1.5 GB PyTorch) | High (Memory crash) | High | **REJECT** |
| **Protect AI Rebuff** | Vector similarity prompt shield | Apache-2.0 | Moderate | 200–500 ms | Heavy (Vector DB + SDK) | Medium (Archived) | High | **REJECT** |
| **Revisor Celery / Redis Queues** | Distributed task worker platform | MIT | N/A | Adds network hop | Heavy (Redis + Celery) | Medium (Extra daemon) | High | **REJECT** |
| **VirusTotal File Upload** | External raw file submission | N/A | High | High bandwidth | Zero | **Critical (Privacy Leak)** | Low | **REJECT** |
| **AbuseIPDB IP Reputation** | Network IoC verification | Free Tier API | High | 100–250 ms | Zero (uses `httpx`) | Low | Low | **DEFER** |
| **In-Memory FAISS Vector Index** | Semantic vector similarity | MIT | Moderate | 50–100 ms | Moderate (C++ binary) | Low | Moderate | **DEFER** |

---

## 2. Decision Summary Breakdown

* **ADOPT (3 Components)**:
  1. `yara-python`
  2. VirusTotal API v3 Client (Hash-First)
  3. `mirzaakhi/prompt-injection-detection-dataset` (Evaluation Benchmark)
* **ADAPT (3 Techniques)**:
  1. Recursive Multi-Encoding Normalization (from Prompt Shield)
  2. Multi-Signal Transparent Score Fusion (from Prompt Armor)
  3. Multi-Engine Normalized Detection Result Schema (from Revisor)
* **REFERENCE ONLY (3 Projects)**:
  1. `deadbits/vigil-llm`
  2. `Neo23x0/signature-base`
  3. `elastic/protections-artifacts`
* **DEFER (2 Components)**:
  1. AbuseIPDB Network CTI
  2. In-Memory Vector Similarity
* **REJECT (4 Approaches)**:
  1. PyTorch / HuggingFace Transformers (Memory bloat)
  2. Celery / Redis Distributed Queues (Infrastructure bloat)
  3. Protect AI Rebuff (Archived)
  4. Raw File Upload to External APIs (Data privacy violation)
