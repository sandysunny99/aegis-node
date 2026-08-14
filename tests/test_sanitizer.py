"""
Aegis Node — Test Suite: Sanitizer Engine
Tests that all remediation transformations produce correct, safe output.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.sanitizer import (
    _remediate_binary_cell,
    _remediate_formula_cell,
    _remediate_script_cell,
    _remediate_sql_cell,
    _sanitize_cell_value,
)


class TestFormulaSanitization:
    """Verify formula injection neutralization."""

    def test_prefix_equals_formula(self):
        new_val, changed, rule_id = _remediate_formula_cell("=SUM(1+1)")
        assert changed is True
        assert new_val.startswith("'")
        assert "FORM" in rule_id

    def test_prefix_dde_payload(self):
        new_val, changed, rule_id = _remediate_formula_cell("=cmd|' /C calc'!A0")
        assert changed is True
        assert new_val.startswith("'")

    def test_hyperlink_prefix(self):
        new_val, changed, rule_id = _remediate_formula_cell('=HYPERLINK("http://evil.com","Click")')
        assert changed is True
        assert new_val.startswith("'")
        assert rule_id == "FORM-003"

    def test_safe_value_unchanged(self):
        new_val, changed, _ = _remediate_formula_cell("normal@email.com")
        assert changed is False
        assert new_val == "normal@email.com"

    def test_prefix_makes_value_safe(self):
        """Prefixing with ' must make formula inert in Excel."""
        malicious = "=1+1"
        new_val, changed, _ = _remediate_formula_cell(malicious)
        assert new_val == "'=1+1"
        # Verify prefixed value does NOT start formula trigger
        import re
        assert not re.match(r'^\s*[=+\-@|]', new_val)


class TestScriptSanitization:
    """Verify script injection neutralization."""

    def test_script_tag_removed(self):
        new_val, changed, _ = _remediate_script_cell("<script>alert(1)</script>")
        assert changed is True
        assert "<script>" not in new_val
        assert "[script_removed]" in new_val

    def test_javascript_protocol_neutralized(self):
        new_val, changed, _ = _remediate_script_cell("javascript:alert(1)")
        assert changed is True
        assert "javascript:" not in new_val
        assert "[js_removed]" in new_val

    def test_eval_call_neutralized(self):
        new_val, changed, _ = _remediate_script_cell("eval(malicious_code)")
        assert changed is True
        assert "eval(" not in new_val
        assert "[eval_removed]" in new_val

    def test_safe_text_unchanged(self):
        new_val, changed, _ = _remediate_script_cell("This is a normal description.")
        assert changed is False


class TestSQLSanitization:
    """Verify SQL injection neutralization."""

    def test_or_1_equals_1_full_removal(self):
        """HIGH severity OR injection → entire field wiped to [REMOVED]."""
        new_val, changed, _ = _remediate_sql_cell("' OR '1'='1' --", force_full_remove=True)
        assert changed is True
        assert new_val == "[REMOVED]"

    def test_union_select_full_removal(self):
        """HIGH severity UNION SELECT → entire field wiped to [REMOVED]."""
        new_val, changed, _ = _remediate_sql_cell("UNION SELECT * FROM users", force_full_remove=True)
        assert changed is True
        assert new_val == "[REMOVED]"

    def test_safe_text_unchanged(self):
        new_val, changed, _ = _remediate_sql_cell("User submitted a valid comment.")
        assert changed is False

    def test_full_removal_even_without_force_flag(self):
        """
        SQLI-001 and SQLI-002 are in _SQL_HIGH_SEVERITY_RULES, so they trigger full
        removal regardless of force_full_remove. This documents the intentional design.
        """
        # With force_full_remove=False, the rule set check still triggers full removal
        new_val, changed, rule_id = _remediate_sql_cell("' OR '1'='1' --", force_full_remove=False)
        assert changed is True
        # Both SQLI rules are HIGH severity by design — full removal is expected
        assert new_val == "[REMOVED]"
        assert rule_id == "SQLI-001"

    def test_pipeline_uses_full_removal_by_default(self):
        """The full _sanitize_cell_value pipeline always uses full removal for SQL."""
        new_val, actions = _sanitize_cell_value("' OR '1'='1'", "email", "2")
        assert new_val == "[REMOVED]"
        rule_ids = {a.rule_id for a in actions}
        assert "SQLI-001" in rule_ids


class TestNullByteSanitization:
    """Verify null byte removal."""

    def test_null_bytes_stripped(self):
        new_val, changed, rule_id = _remediate_binary_cell("before\x00after")
        assert changed is True
        assert "\x00" not in new_val
        assert new_val == "beforeafter"
        assert rule_id == "BIN-001"

    def test_multiple_null_bytes(self):
        new_val, changed, _ = _remediate_binary_cell("a\x00b\x00c")
        assert "\x00" not in new_val
        assert new_val == "abc"

    def test_safe_value_unchanged(self):
        new_val, changed, _ = _remediate_binary_cell("clean text")
        assert changed is False


class TestCellSanitizationPipeline:
    """Verify that the full pipeline applies all transformations correctly."""

    def test_combined_formula_and_null_byte(self):
        value = "=SUM(\x001+1)"
        new_val, actions = _sanitize_cell_value(value, "col", "1")
        # Null byte should be removed AND formula should be prefixed
        assert "\x00" not in new_val
        rule_ids = {a.rule_id for a in actions}
        assert "BIN-001" in rule_ids
        assert any(r.startswith("FORM") for r in rule_ids)

    def test_no_changes_for_clean_value(self):
        new_val, actions = _sanitize_cell_value("Completely safe value", "col", "1")
        assert new_val == "Completely safe value"
        assert len(actions) == 0

    def test_actions_record_correct_location(self):
        _, actions = _sanitize_cell_value("=HYPERLINK(evil)", "my_col", "42")
        assert any("my_col" in a.location for a in actions)
        assert any("42" in a.location for a in actions)


class TestMalwareAndFormatSanitization:
    """Verify malware removal, sample_after truncation, and TXT/Parquet support."""

    def test_eicar_cell_removed(self):
        eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        new_val, actions = _sanitize_cell_value(eicar_str, "payload", "0")
        assert new_val == "[REMOVED]"
        assert len(actions) == 1
        assert actions[0].rule_id == "MAL-001"
        assert actions[0].sample_after == "[REMOVED]"

    def test_sample_after_truncated(self):
        long_formula = "=HYPERLINK('http://malicious-site.example.com/exploit/very/long/path/that/exceeds/fifty/characters')"
        _, actions = _sanitize_cell_value(long_formula, "url", "1")
        assert len(actions) >= 1
        assert len(actions[0].sample_after) <= 50

    def test_txt_file_sanitization(self, tmp_path):
        from scanner.sanitizer import sanitize_file
        txt_file = tmp_path / "threats.txt"
        txt_file.write_text("safe line\n=cmd|' /C calc'!A0\n<script>alert(1)</script>\n", encoding="utf-8")
        result = sanitize_file(str(txt_file), "txt")
        assert result.error is None
        assert result.changes_count >= 2
        content = result.sanitized_bytes.decode("utf-8")
        assert "[cmd_neutralized]" in content
        assert "[script_removed]" in content

    def test_eicar_csv_file_remediation_rescan(self, tmp_path):
        from scanner.engine import run_scan
        from scanner.sanitizer import sanitize_file
        eicar_file = tmp_path / "eicar.csv"
        eicar_file.write_text("id,payload\n1,X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n", encoding="utf-8")
        
        # Scan before
        scan_before = run_scan(str(eicar_file))
        assert scan_before.verdict == "malicious"
        
        # Remediate
        res = sanitize_file(str(eicar_file), "csv")
        clean_file = tmp_path / "eicar_clean.csv"
        clean_file.write_bytes(res.sanitized_bytes)
        
        # Scan after -> must be clean with 0 threats
        scan_after = run_scan(str(clean_file))
        assert scan_after.verdict == "clean"
        assert scan_after.threats_found_count == 0

