# Aegis Node — YARA Rule Provenance Registry

**Location**: `backend/rules/yara/`  
**License**: Apache-2.0 / MIT  
**Validation Policy**: Every rule is tested against both positive malicious fixtures and negative benign research text.

---

## Rule Registry

| Rule ID | File Name | Rule Identifier | Category | Severity | License | Purpose & Threat Target | Provenance / Author |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **YARA-001** | `embedded_pe_dropper.yar` | `Embedded_PE_Executable` | `malware_artifact` | `CRITICAL` | Apache-2.0 | Detects embedded raw MZ/PE executable headers or hex-encoded DOS stagers (`4d5a9000...`) within data cells. | Aegis Node Security Team |
| **YARA-002** | `eicar_standard_test.yar` | `EICAR_Test_Signature` | `malware_signature` | `HIGH` | Apache-2.0 | Identifies standard EICAR test string across tabular cells. | European Institute for Computer Antivirus Research |
| **YARA-003** | `suspicious_shellcode_nopsled.yar` | `Shellcode_NOP_Sled` | `shellcode` | `HIGH` | Apache-2.0 | Detects x86/x64 NOP sleds (`\x90\x90...`) and stack frame function prologs in binary/text fields. | Aegis Node Security Team |
| **YARA-004** | `webshell_dynamic_eval.yar` | `Webshell_Dynamic_Eval` | `script_injection` | `CRITICAL` | Apache-2.0 | Flags dynamic execution one-liners (`eval(base64_decode(...))`, `Runtime.getRuntime().exec(...)`). | Aegis Node Security Team |

---

## Testing & Quality Control
- **Positive Testing**: Tested against synthetically crafted payloads in `tests/test_yara_scanner.py`.
- **Negative Testing**: Tested against benign research CSVs (e.g. security papers discussing WannaCry, Mimikatz, Metasploit) to ensure **0 false positives** on plain text research metadata.
