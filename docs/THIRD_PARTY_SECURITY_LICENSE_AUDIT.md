# Third-Party Security & License Audit

**Document Type**: License Compliance & Security Assessment  
**Compliance Standard**: Permissive Open-Source Licensing (MIT / Apache-2.0 / BSD)  

---

## 1. Candidate License Evaluation Matrix

| Project / Repository | Repository URL | License | Compatibility Status | Maintenance Status | Security Risk Assessment | Decision |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **yara-python** | VirusTotal/yara-python | BSD-3-Clause | **APPROVED** | Active (v4.5.x) | Low (Mature C library binding) | **ADOPT (Library)** |
| **Revisor** | a-sarja/Revisor | MIT | **APPROVED** | Active | Low | **REFERENCE ONLY** (Multi-engine architecture) |
| **Vigil** | deadbits/vigil-llm | Apache-2.0 | **APPROVED** | Active | Medium (Heavy transformer dependencies) | **ADAPT / REFERENCE** (Modular scanner concept) |
| **Prompt Armor** | prompt-armor/prompt-armor | MIT / Apache-2.0 | **APPROVED** | Active | Medium (FAISS vector stack) | **ADAPT (Normalization & Regex layers)** |
| **Prompt Shield** | mthamil107/prompt-shield | MIT | **APPROVED** | Active | Low | **ADAPT (Multi-encoding decoders)** |
| **Rebuff** | protectai/rebuff | Apache-2.0 | **REVIEW REQUIRED** | **ARCHIVED by Maintainer** | Medium (Stale dependencies, unmaintained) | **REJECT / REFERENCE ONLY** |
| **ClamAV Client** | Custom / In-house | MIT | **APPROVED** | N/A (Aegis in-house) | Low (Zero-dependency TCP socket client) | **MAINTAIN (Current)** |
| **Prompt Injection Dataset** | mirzaakhi/prompt-injection-detection-dataset | MIT / CC-BY-4.0 | **APPROVED** | Active | Zero (Evaluation dataset only) | **ADOPT (Benchmark Dataset)** |

---

## 2. License Compatibility & Linking Architecture

### A. GPL Isolation (ClamAV Daemon vs. Aegis Node Client)
- **ClamAV Engine**: Licensed under GPLv2.
- **Compliance Isolation**: Aegis Node does **NOT** link against ClamAV source code or libraries. Aegis Node communicates with the external `clamd` process over a network TCP socket (`INSTREAM` command). Under open-source licensing law, socket-based protocol communication preserves Aegis Node's permissive MIT/Apache-2.0 license integrity without triggering copyleft requirements.

### B. BSD & Apache-2.0 Inclusions (`yara-python`)
- `yara-python` is licensed under BSD 3-Clause, permitting commercial, academic, and open-source distribution provided standard copyright notices are retained in `docs/THIRD_PARTY_COMPONENTS.md`.

---

## 3. Dependency Security Vulnerability Screening

| Package | Version | Known CVEs | Memory Safety | Integration Sandbox |
| :--- | :--- | :--- | :--- | :--- |
| `yara-python` | $\ge$ 4.3.0 | None in current stable | C Extension (Bound memory) | Invoked in isolated threadpool |
| `httpx` | $\ge$ 0.27.0 | None | Pure Python | Async non-blocking network calls |
| `pandas` | $\ge$ 2.2.0 | None | C/Cython | Streamed chunk processing |
| `pydantic` | $\ge$ 2.8.0 | None | Rust-accelerated core | Strict data model validation |

---

## 4. Final Compliance Verdict

All candidate components selected for adoption and adaptation comply strictly with permissive licensing requirements (MIT, Apache-2.0, BSD-3). No viral GPL/AGPL source code is copied into Aegis Node.
