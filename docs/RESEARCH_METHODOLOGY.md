# Aegis Node — Research Methodology & Scientific Evaluation

**Project**: Aegis Node: An AI-Assisted Framework for Secure Dataset Threat Detection and Remediation  
**Academic Level**: M.Tech Thesis / Research Methodology Specification  

---

## 1. Research Problem & Objective

Modern data pipelines and machine learning workflows ingest massive volumes of semi-structured and tabular datasets from untrusted public repositories, crowdsourced annotators, and automated web scrapers. While traditional security controls focus on network perimeters and binary endpoints, dataset files (CSV, Parquet, JSON, XLSX) are frequently weaponized as attack vectors via:
1. **Spreadsheet Formula Injection (CSV Injection / DDE)**: Abusing client-side formula evaluation (`=CMD|`, `=HYPERLINK`) to achieve remote code execution upon analyst export.
2. **Polyglot & Binary Droppers**: Hiding executable headers (PE, ELF, Mach-O) or raw shellcode inside tabular text fields.
3. **Data Poisoning & Adversarial Prompts**: Injecting system prompt overrides into training corpuses.

Aegis Node provides a **deterministic multi-stage inspection, explanation, and remediation framework** that marries deterministic detection rules with evidence-grounded AI explanation and automated re-verification.

---

## 2. Formal Architecture Pipeline

$$\text{Untrusted Dataset} \xrightarrow{\text{Upload Stream}} \text{SHA-256} \xrightarrow{\text{Stage 0}} \text{Raw Bytes Scan} \xrightarrow{\text{Stage 0.5}} \text{Heuristics} \xrightarrow{\text{Stage 1}} \text{ClamAV} \xrightarrow{\text{Stage 2}} \text{Content Rules} \xrightarrow{\text{Aggregator}} \text{Evidence JSON} \xrightarrow{\text{AI Assistant}} \text{Contextual Explanation} \xrightarrow{\text{Deterministic Sanitizer}} \text{Sanitized Copy} \xrightarrow{\text{Mandatory Re-Scan}} \text{Verification Metric}$$

```
                ┌──────────────────────────────────────────────┐
                │          Untrusted Dataset Upload            │
                └──────────────────────┬───────────────────────┘
                                       │ (Stream to disk, SHA-256)
                                       ▼
                ┌──────────────────────────────────────────────┐
                │             Multi-Stage Scanner              │
                │ ├─ Stage 0: Raw Bytes (EICAR, PE/ELF)        │
                │ ├─ Stage 0.5: Heuristic Entropy & APIs       │
                │ ├─ Stage 1: ClamAV Antivirus Daemon          │
                │ └─ Stage 2: Content Rules (OWASP Injection)  │
                └──────────────────────┬───────────────────────┘
                                       │ (Compact Evidence Payload)
                                       ▼
                ┌──────────────────────────────────────────────┐
                │             AI Contextual Engine             │
                │  - Grounded in <UNTRUSTED_DATA> evidence     │
                │  - Pydantic schema validation & bounds       │
                │  - No file mutation permissions              │
                └──────────────────────┬───────────────────────┘
                                       │ (Remediation recommendations)
                                       ▼
                ┌──────────────────────────────────────────────┐
                │            Deterministic Sanitizer           │
                │  - In-place string neutralization            │
                │  - Schema & column structure preservation    │
                │  - Original dataset left immutable           │
                └──────────────────────┬───────────────────────┘
                                       │ (Sanitized artifact)
                                       ▼
                ┌──────────────────────────────────────────────┐
                │          Automated Verification Re-Scan      │
                │  - Second scan across all inspection stages  │
                │  - Threat Reduction % & Integrity Score      │
                │  - Verified Download Token Issuance          │
                └──────────────────────────────────────────────┘
```

---

## 3. Core Evaluation Metrics

Aegis Node evaluates datasets across four quantitative dimensions:

### 1. Composite Threat Risk Score ($R$)
$$R = \min\left( \sum_{i=1}^{N} w_i \cdot s(f_i) + 3.0 \cdot H_{\text{risk}}, 10.0 \right)$$
where $s(f_i)$ is the severity weight of finding $f_i$ ($\text{critical}=3.5, \text{high}=2.0, \text{medium}=1.0, \text{low}=0.2$), and $H_{\text{risk}} \in [0.0, 1.0]$ is the heuristic anomaly score.

### 2. Threat Reduction Percentage ($\text{TRP}$)
$$\text{TRP} = \begin{cases} 
\max\left(0, \frac{R_{\text{orig}} - R_{\text{san}}}{R_{\text{orig}}} \times 100\right) & \text{if } R_{\text{orig}} > 0 \\
100\% & \text{if } N_{\text{remaining}} = 0 \\
0\% & \text{otherwise}
\end{cases}$$

### 3. Data Integrity Preservation Score ($\text{IPS}$)
$$\text{IPS} = \max\left(0, 100 \times \left(1 - \frac{\text{Changes Count}}{\text{Total Fields Scanned}}\right)\right)$$

### 4. Scan Coverage Percentage ($\text{SCP}$)
$$\text{SCP} = \left(\frac{\text{Rows Inspected}}{\text{Rows Total}}\right) \times 100$$

---

## 4. Key Scientific Distinctions

1. **Deterministic Authority vs AI Reasoning**: The AI is never the primary malware authority; it analyzes structured evidence generated by deterministic scanners and cannot override a scanner verdict.
2. **Metadata Reference vs Artifact Detection**: Threat intelligence terminology (e.g. "WannaCry", "ransomware") in analysis datasets does not trigger false-positive malware verdicts.
3. **Non-Destructive Sanitization**: Original datasets and hashes are immutable; sanitized versions are produced separately and subjected to automated re-scan verification.
