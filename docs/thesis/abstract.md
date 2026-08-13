# Aegis Node — Thesis Abstract

**Title**: Aegis Node — An AI-Assisted Multi-Stage Framework for Secure Dataset Threat Detection, Remediation & Verification  
**Author**: Siddharth Goud  
**Degree**: Master of Technology (M.Tech) in Computer Science & Engineering / Cybersecurity  
**Institution**: Department of Computer Science & Engineering  

---

## Abstract

Enterprise machine learning (ML) workflows and analytical data engineering pipelines increasingly rely on bulk ingestion of tabular and document datasets (CSV, JSON, JSONL, Parquet) received from untrusted third-party integrators and public data repositories. While traditional perimeter security controls adequately protect data in transit (TLS) and at rest (IAM), they fail to inspect dataset *content* for application-layer payloads. Embedded Excel formula triggers (`=CMD()`, `+SUM()`, `DDE()`), Cross-Site Scripting (`<script>`, `javascript:`), SQL injection fragments (`' OR '1'='1`), and control byte anomalies (`\x00`) bypass network firewalls and execute inside data analyst spreadsheet tools, web analytics dashboards, or downstream relational database queries. Signature-based antivirus software (e.g., ClamAV) detects compiled malware binaries but remains ineffective against text-based application injection attacks inside valid structured file formats.

To address this security gap, this thesis introduces **Aegis Node**, a lightweight, multi-stage threat detection, remediation, and verification framework. Aegis Node combines ClamAV signature scanning with a deterministic format-aware rule engine (inspecting formula, script, SQL, and binary threats), integrated with downstream Large Language Model (LLM) contextual analysis powered by Gemini 3.6 Flash. To preserve data privacy and bound cloud API token costs, the LLM receives *compact scanner evidence only*—raw dataset files, database tables, or sensitive bytes are never transmitted to external APIs. Furthermore, Aegis Node provides deterministic threat remediation (single-quote formula escaping, script tag stripping, SQL payload neutralization) and automated post-remediation re-scan verification to quantitatively measure threat reduction without corrupting dataset structural schemas or altering read-only original files.

Aegis Node was evaluated against a synthetic benchmark corpus of 100 datasets (20 clean, 80 threat across formula, script, SQL, and mixed categories). In comparative experimental evaluations, the combined detection engine achieved an observed F1 score of **1.0000** with an average scan latency of **1.73 ms** (577 datasets/sec throughput). The remediation pipeline achieved an average **79.41% threat reduction** and a **66.25% 100% clean success rate** across threat datasets. The framework provides a reproducible, lightweight, and academically defensible security baseline for automated dataset ingestion.

**Keywords**: Dataset Security, Formula Injection, Script Injection, SQL Injection, ClamAV, Large Language Models, Data Sanitization, Threat Remediation, Cybersecurity.
