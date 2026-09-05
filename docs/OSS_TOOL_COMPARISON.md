# Open-Source Security Tool Comparison Matrix

**Objective**: Systematic comparison of candidate open-source security tools, detection engines, and AI defense frameworks against Aegis Node's architectural requirements.

---

## 1. Multi-Tool Comparison Table

| Tool / Framework | Primary Purpose | License | Maintenance | Accuracy Potential | RAM / Dependency Complexity | Privacy Model | Decision for Aegis Node |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **ClamAV (`clamd`)** | Known malware signature detection | GPL-2.0 (Socket API) | Highly Active | High for standard malware binaries | Moderate (Daemon 1.2 GB; Zero in client) | 100% Local / Private | **MAINTAIN (Current Stage 1)** |
| **YARA (`yara-python`)** | Binary & text pattern matching | BSD-3-Clause | Highly Active | Very High for custom dataset vectors | Very Low (< 10 MB RAM) | 100% Local / Private | **ADOPT (Stage 1.5 Detection Engine)** |
| **VirusTotal API v3** | Multi-engine hash reputation (70+ AVs) | Proprietary / Free Tier | Active API | Maximum for known threats | Zero (Lightweight HTTP calls) | **100% Private (Hash-first; zero file upload)** | **ADOPT (Optional Enrichment)** |
| **Revisor** | Multi-engine ClamAV + YARA + VT scanner | MIT | Active | High | High (Requires Celery + Redis + DB) | Unsafe (Uploads raw files) | **REFERENCE ONLY (Architecture Concept)** |
| **Vigil (`vigil-llm`)** | Prompt injection detection framework | Apache-2.0 | Active | High | High (Requires PyTorch + Transformers + ChromaDB) | 100% Local | **ADAPT (Modular scanner concept & YARA rules)** |
| **Prompt Armor** | 5-layer offline prompt injection defense | MIT | Active | High | Moderate (Requires FAISS vector stack) | 100% Local | **ADAPT (Normalization & Score Fusion)** |
| **Prompt Shield** | Normalization & encoding threat detector | MIT | Active | Very High for obfuscated payloads | Very Low (Pure Python regex & decoders) | 100% Local | **ADAPT (Multi-Encoding Normalizer)** |
| **Rebuff** | Prompt injection prompt shield | Apache-2.0 | **ARCHIVED** | Moderate | Moderate (Pinecone/Vector + OpenAI) | Cloud-dependent | **REJECT (Archived & Cloud-dependent)** |
| **AbuseIPDB** | IP reputation for C2 / Botnets | Free API | Active API | High for network IoCs | Zero (Lightweight HTTP) | Private (Query only IP) | **DEFER (Secondary CTI)** |

---

## 2. Detailed Technical Comparison of Prompt Injection Approaches

```
+----------------------------------------------------------------------------------------------------+
| APPROACH             | LATENCY     | RAM USAGE  | OBFUSCATION DEFENSE | HARD NEGATIVE ACCURACY     |
+----------------------------------------------------------------------------------------------------+
| Pure Regex (Baseline)| < 1 ms      | < 1 MB     | ⚠️ Poor (Bypassed)  | ⚠️ Moderate (Keyword bias) |
| Normalization + Regex| < 2 ms      | < 2 MB     | ✅ High (Decodes)   | ✅ High (Context-aware)    |
| Heavy Transformers   | 1500–2500 ms| 800–1500 MB| ✅ Very High        | ✅ Very High               |
| Vector Embeddings    | 80–150 ms   | 200–400 MB | ⚠️ Moderate         | ⚠️ Moderate (False matches)|
+----------------------------------------------------------------------------------------------------+
```

### Strategic Decision:
Aegis Node will **NOT** adopt heavy PyTorch/Transformer stacks (which would crash Render's 512 MB memory boundary and introduce 2-second scan delays). Instead, Aegis Node will **ADAPT** the multi-encoding normalization pipeline from Prompt Shield and the multi-signal score fusion model from Prompt Armor.
