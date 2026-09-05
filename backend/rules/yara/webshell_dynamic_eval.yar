/*
  Aegis Node Curated YARA Rule: Webshell Dynamic Eval Stager
  Rule ID: YARA-004
  License: Apache-2.0 / MIT
  Purpose: Identifies dynamic code evaluation patterns commonly used in PHP/JSP webshell droppers.
  Author: Aegis Node Security Engineering
*/

rule Webshell_Dynamic_Eval {
    meta:
        rule_id = "YARA-004"
        description = "Detects PHP/JSP dynamic eval execution stagers"
        severity = "CRITICAL"
        category = "script_injection"
        author = "Aegis Node"
    strings:
        $php_eval_b64 = "eval(base64_decode(" nocase
        $php_eval_gz = "eval(gzinflate(base64_decode(" nocase
        $php_system_get = "system($_GET[" nocase
        $php_passthru = "passthru($_POST[" nocase
        $php_shell_exec = "shell_exec($_REQUEST[" nocase
        $jsp_runtime = "Runtime.getRuntime().exec(" nocase
    condition:
        any of them
}
