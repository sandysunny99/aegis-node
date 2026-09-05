/*
  Aegis Node Curated YARA Rule: Embedded PE Executable Dropper
  Rule ID: YARA-001
  License: Apache-2.0 / MIT
  Purpose: Detects raw or hex/base64 encoded Windows PE executables embedded within tabular cells or text.
  Author: Aegis Node Security Engineering
*/

rule Embedded_PE_Executable {
    meta:
        rule_id = "YARA-001"
        description = "Detects raw or hex-encoded Windows PE executable embedded in dataset"
        severity = "CRITICAL"
        category = "malware_artifact"
        author = "Aegis Node"
    strings:
        // Raw MZ header followed by PE signature
        $mz_raw = { 4D 5A }
        $pe_sig = "PE\x00\x00"
        // Hex encoded MZ header with DOS stub stub (4d5a9000...)
        $mz_hex = "4d5a9000" nocase
        $mz_hex_spaced = "4d 5a 90 00" nocase
    condition:
        ($mz_raw at 0 and $pe_sig) or $mz_hex or $mz_hex_spaced
}
