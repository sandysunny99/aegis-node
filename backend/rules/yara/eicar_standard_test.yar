/*
  Aegis Node Curated YARA Rule: EICAR Standard Antivirus Test
  Rule ID: YARA-002
  License: Apache-2.0 / MIT
  Purpose: Identifies the standard EICAR test string in files or dataset cells.
  Author: Aegis Node Security Engineering
*/

rule EICAR_Test_Signature {
    meta:
        rule_id = "YARA-002"
        description = "Standard EICAR Antivirus Test Signature"
        severity = "HIGH"
        category = "malware_signature"
        author = "Aegis Node"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
