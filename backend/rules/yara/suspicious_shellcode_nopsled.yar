/*
  Aegis Node Curated YARA Rule: Shellcode NOP Sled Stager
  Rule ID: YARA-003
  License: Apache-2.0 / MIT
  Purpose: Detects x86/x64 NOP sleds (\x90) combined with shellcode call/jump stagers in data.
  Author: Aegis Node Security Engineering
*/

rule Shellcode_NOP_Sled {
    meta:
        rule_id = "YARA-003"
        description = "Detects x86/x64 NOP sled shellcode stager in dataset cell"
        severity = "HIGH"
        category = "shellcode"
        author = "Aegis Node"
    strings:
        // 16 continuous NOP bytes
        $nop_raw = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        // Hex escaped \x90\x90...
        $nop_hex = "\\x90\\x90\\x90\\x90\\x90\\x90\\x90\\x90" nocase
        // Shellcode function prolog: push ebp; mov ebp, esp
        $prolog_32 = { 55 89 E5 }
        // 64-bit prolog: push rbp; mov rbp, rsp
        $prolog_64 = { 55 48 89 E5 }
    condition:
        ($nop_raw or $nop_hex) or ($nop_raw and ($prolog_32 or $prolog_64))
}
