# Aegis Node: Demo Script (7-10 minutes)

## 0:00 — Introduction
"Welcome to the Aegis Node demo. Aegis is a dataset-centric security framework that relies on a defense-in-depth architecture. Today, I'll walk you through a complete lifecycle of an uploaded dataset containing a mix of benign data, malicious URLs, and prompt injection attempts."

## 1:00 — Upload
"We begin by uploading our synthetic dataset. The system immediately checks the file structure and rejects unsupported binary formats. Once accepted, it moves into the static analysis pipeline without ever executing the contents."

## 2:00 — Deterministic Scan
"Here we see the deterministic scan results. ClamAV and our YARA-style heuristics have analyzed the content. Notice the file is identified by its SHA-256 hash. The deterministic verdict is currently flagged as 'suspicious'."

## 3:00 — TI
"Now, we look at the Threat Intelligence enrichment panel. Aegis extracted the IP addresses and URLs from the dataset and performed bounded, lookup-only queries against URLhaus and AbuseIPDB. We see corroborated evidence that one of the URLs is malicious."

## 4:00 — Guardrail
"Before passing the data to the LLM for explanation, our native AI Guardrail steps in. In this case, the guardrail detected instruction-like text intended to manipulate the LLM. It has triggered a 'RESTRICT' state, stripping the dangerous payload while preserving metadata."

## 5:00 — LLM
"With the guardrail in place, the LLM safely analyzes the restricted context. The LLM provides a summary of why the dataset was flagged. Notice that the LLM cannot change the deterministic verdict; it acts strictly as an interpreter."

## 6:00 — Remediation
"We now initiate remediation. Aegis deterministically sanitizes the dataset—for instance, by neutralizing script tags and removing the malicious URL."

## 7:00 — Re-scan
"Crucially, Aegis does not just assume remediation worked. The newly sanitized file is forced through a mandatory re-scan against all deterministic rules."

## 8:00 — Verification
"The re-scan completes. The new verdict is 'clean_verified'. This verification step is mandatory before the system allows the user to download the sanitized file."

## 9:00 — Final report
"We can now view the final security report. It traces the full provenance: from the initial deterministic finding, the TI conflict/corroboration, the AI guardrail intervention, to the successful verification."

## 10:00 — Closing statement
"Throughout this process, Aegis Node demonstrated its core principle: no single layer is trusted. Residual AI-layer uncertainty was contained by independent deterministic controls. Thank you."
