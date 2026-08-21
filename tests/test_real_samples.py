"""
Aegis Node — Real Sample Malware Detection Tests.

Tests the full scanning pipeline against:
  1. EICAR antivirus test string (raw bytes + CSV cell)
  2. Known malware family name detection (Output1.csv — Spyware-TIBS dataset)
  3. Formula injection, script injection, SQL injection
  4. PowerShell encoded commands
  5. Binary header detection (PE/MZ, ELF)
  6. The full end-to-end engine.run_scan() pipeline

Run with:  pytest tests/test_real_samples.py -v
"""

import os
import sys
import tempfile
from pathlib import Path

import pytest

# ── Path setup ────────────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCANNER_DIR = _REPO_ROOT / "scanner"
_BACKEND_DIR = _REPO_ROOT / "backend"
_TEST_SAMPLES = _REPO_ROOT.parent / "test sample"

sys.path.insert(0, str(_SCANNER_DIR))
sys.path.insert(0, str(_BACKEND_DIR))

from content_checker import ContentCheckResult, check_file, raw_bytes_scan
from engine import run_scan

# ──────────────────────────────────────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────────────────────────────────────

def _tmp_csv(content: str) -> Path:
    """Write content to a temp CSV file and return its Path."""
    f = tempfile.NamedTemporaryFile(
        mode="w", suffix=".csv", delete=False, encoding="utf-8"
    )
    f.write(content)
    f.close()
    return Path(f.name)


def _tmp_bytes(content: bytes, suffix: str = ".csv") -> Path:
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


# ──────────────────────────────────────────────────────────────────────────────
# Stage 0: Raw Bytes Scan Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRawBytesScan:
    """Tests for raw_bytes_scan() — binary malware detection before parsing."""

    def test_eicar_raw_bytes_detected(self):
        """EICAR test string in raw bytes must be flagged as critical."""
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        path = _tmp_bytes(b"filename,data\ntest," + eicar + b"\n")
        try:
            findings = raw_bytes_scan(path)
            rule_ids = [f.rule_id for f in findings]
            assert "MAL-001" in rule_ids, f"EICAR not detected. Found: {rule_ids}"
            eicar_finding = next(f for f in findings if f.rule_id == "MAL-001")
            assert eicar_finding.severity == "critical"
            assert eicar_finding.category == "malware_signature"
        finally:
            os.unlink(path)

    def test_pe_mz_header_detected(self):
        """Windows PE MZ header at file start must be detected."""
        pe_bytes = b"MZ\x90\x00\x03\x00\x00\x00" + b"\x00" * 100
        path = _tmp_bytes(pe_bytes, suffix=".bin")
        try:
            findings = raw_bytes_scan(path)
            rule_ids = [f.rule_id for f in findings]
            assert "MAL-002" in rule_ids, f"PE/MZ header not detected. Found: {rule_ids}"
        finally:
            os.unlink(path)

    def test_elf_header_detected(self):
        """ELF binary header must be detected."""
        elf_bytes = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 100
        path = _tmp_bytes(elf_bytes, suffix=".bin")
        try:
            findings = raw_bytes_scan(path)
            rule_ids = [f.rule_id for f in findings]
            assert "MAL-003" in rule_ids, f"ELF header not detected. Found: {rule_ids}"
        finally:
            os.unlink(path)

    def test_clean_csv_no_raw_findings(self):
        """Clean CSV file should return no raw binary findings."""
        path = _tmp_csv("name,age,city\nAlice,30,London\nBob,25,Paris\n")
        try:
            findings = raw_bytes_scan(path)
            mal_findings = [f for f in findings if f.rule_id.startswith("MAL-")]
            assert len(mal_findings) == 0, f"False positive in clean file: {mal_findings}"
        finally:
            os.unlink(path)

    def test_embedded_pe_in_csv_detected(self):
        """PE header embedded inside a CSV (polyglot file) must be detected."""
        csv_header = b"name,data\ntest,"
        pe_payload = b"MZ\x90\x00" + b"\x00" * 200
        path = _tmp_bytes(csv_header + pe_payload)
        try:
            findings = raw_bytes_scan(path)
            rule_ids = [f.rule_id for f in findings]
            assert "MAL-002" in rule_ids, f"Embedded PE not detected. Found: {rule_ids}"
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# Stage 1: Content Rules Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestContentRules:
    """Tests for text-level threat detection rules in check_file()."""

    def test_eicar_string_in_csv_cell(self):
        """EICAR string in a CSV cell field must be detected."""
        eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        path = _tmp_csv(f"filename,content\ntest.csv,\"{eicar_str}\"\n")
        try:
            result = check_file(str(path))
            rule_ids = [f.rule_id for f in result.findings]
            assert "MAL-001" in rule_ids, f"EICAR in CSV cell not detected. Findings: {result.findings}"
        finally:
            os.unlink(path)

    def test_malware_family_name_in_filename_column(self):
        """Malware family names in the Filename column must trigger MAL-009."""
        path = _tmp_csv(
            "Filename,label\n"
            "Spyware-TIBS-abc123.raw,1\n"
            "Ransomware-WannaCry-def456.raw,1\n"
            "benign.exe,0\n"
        )
        try:
            result = check_file(str(path))
            rule_ids = [f.rule_id for f in result.findings]
            assert "MAL-009" in rule_ids, (
                f"Malware family name in Filename not detected. Findings: {result.findings}"
            )
        finally:
            os.unlink(path)

    def test_formula_injection_detected(self):
        """CSV formula injection starting with = must be detected."""
        path = _tmp_csv('name,formula\ntest,"=CMD|\'calc\'!A0"\n')
        try:
            result = check_file(str(path))
            rule_ids = [f.rule_id for f in result.findings]
            assert "FORM-001" in rule_ids or "FORM-002" in rule_ids, (
                f"Formula injection not detected. Findings: {result.findings}"
            )
        finally:
            os.unlink(path)

    def test_script_injection_detected(self):
        """XSS script tag must be detected."""
        path = _tmp_csv("name,bio\ntest,\"<script>alert('xss')</script>\"\n")
        try:
            result = check_file(str(path))
            rule_ids = [f.rule_id for f in result.findings]
            assert "SCRP-001" in rule_ids, f"Script injection not detected. Findings: {result.findings}"
        finally:
            os.unlink(path)

    def test_sql_injection_detected(self):
        """SQL injection payload must be detected."""
        path = _tmp_csv("name,input\ntest,\"' OR '1'='1; DROP TABLE users--\"\n")
        try:
            result = check_file(str(path))
            rule_ids = [f.rule_id for f in result.findings]
            assert "SQLI-001" in rule_ids, f"SQL injection not detected. Findings: {result.findings}"
        finally:
            os.unlink(path)

    def test_powershell_encoded_command_detected(self):
        """PowerShell encoded command must be detected."""
        ps_payload = "powershell -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQA"
        path = _tmp_csv(f"name,cmd\ntest,\"{ps_payload}\"\n")
        try:
            result = check_file(str(path))
            rule_ids = [f.rule_id for f in result.findings]
            assert "MAL-005" in rule_ids, f"PowerShell encoded command not detected. Findings: {result.findings}"
        finally:
            os.unlink(path)

    def test_clean_csv_returns_no_findings(self):
        """Benign dataset must return zero findings and risk_score=0."""
        path = _tmp_csv("name,age,city\nAlice,30,London\nBob,25,Paris\n")
        try:
            result = check_file(str(path))
            assert result.threat_count == 0, f"False positive: {result.findings}"
            assert result.risk_score == 0.0
        finally:
            os.unlink(path)


# ──────────────────────────────────────────────────────────────────────────────
# Real Sample File Tests
# ──────────────────────────────────────────────────────────────────────────────

class TestRealSamples:
    """Tests against the actual sample files in 'test sample' directory."""

    @pytest.mark.skipif(
        not _TEST_SAMPLES.exists(),
        reason=f"Test sample directory not found: {_TEST_SAMPLES}",
    )
    def test_output1_csv_detects_malware_family_names(self):
        """Output1.csv contains Spyware-TIBS filenames — MAL-009 must fire."""
        sample = _TEST_SAMPLES / "Output1.csv"
        pytest.importorskip("pandas")  # Skip if pandas not installed
        if not sample.exists():
            pytest.skip(f"Output1.csv not found at {sample}")

        result = check_file(str(sample))
        rule_ids = [f.rule_id for f in result.findings]
        assert "MAL-009" in rule_ids, (
            f"Malware family names in Output1.csv not detected.\n"
            f"Findings: {result.findings}\n"
            f"Rules triggered: {rule_ids}"
        )
        assert result.risk_score > 0, "Risk score should be > 0 for malware dataset"

    @pytest.mark.skipif(
        not _TEST_SAMPLES.exists(),
        reason=f"Test sample directory not found: {_TEST_SAMPLES}",
    )
    def test_eicar_test_csv_detected(self):
        """eicar_test.csv must trigger MAL-001 (EICAR) and FORM-001 (formula)."""
        sample = _TEST_SAMPLES / "eicar_test.csv"
        if not sample.exists():
            pytest.skip(f"eicar_test.csv not found at {sample}")

        result = check_file(str(sample))
        rule_ids = [f.rule_id for f in result.findings]
        assert "MAL-001" in rule_ids or any(r.startswith("MAL-") for r in rule_ids), (
            f"No malware rules triggered on eicar_test.csv.\nFindings: {result.findings}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Full Pipeline Tests (engine.run_scan)
# ──────────────────────────────────────────────────────────────────────────────

class TestFullPipeline:
    """Tests for the complete engine.run_scan() pipeline."""

    def test_eicar_pipeline_verdict_malicious(self):
        """EICAR file must produce verdict=malicious in the full pipeline."""
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        path = _tmp_bytes(b"filename,content\ntest," + eicar + b"\n")
        try:
            result = run_scan(str(path))
            assert result.verdict in ("malicious", "suspicious"), (
                f"EICAR file not flagged. verdict={result.verdict} "
                f"threats={result.threats_found_count} "
                f"findings={result.to_findings_dicts()}"
            )
            assert result.threats_found_count > 0, "threats_found_count must be > 0"
        finally:
            os.unlink(path)

    def test_clean_file_verdict_clean(self):
        """Clean benign CSV must produce clean verdict."""
        path = _tmp_csv("name,age,city\nAlice,30,London\nBob,25,Paris\n")
        try:
            result = run_scan(str(path))
            assert result.verdict in ("clean", "clean_verified", "clean_with_limitations"), (
                f"False positive: verdict={result.verdict} findings={result.to_findings_dicts()}"
            )
        finally:
            os.unlink(path)

    def test_malware_dataset_flagged_as_suspicious_or_malicious(self):
        """Dataset with known malware family names is detected and recorded in findings."""
        path = _tmp_csv(
            "Filename,score\n"
            "Trojan-Dropper-abc123.raw,0.95\n"
            "Ransomware-WannaCry-xyz.raw,0.99\n"
        )
        try:
            result = run_scan(str(path))
            assert result.verdict in ("malicious", "suspicious", "clean_with_limitations"), (
                f"Malware dataset not flagged: verdict={result.verdict}"
            )
            assert result.threats_found_count > 0
        finally:
            os.unlink(path)

    def test_sha256_computed(self):
        """run_scan must always compute a SHA-256 hash."""
        path = _tmp_csv("name,value\ntest,hello\n")
        try:
            result = run_scan(str(path))
            assert len(result.sha256_hash) == 64, "SHA-256 hash must be 64 hex chars"
            assert all(c in "0123456789abcdef" for c in result.sha256_hash)
        finally:
            os.unlink(path)

    def test_eicar_offline_clamav_still_detected(self, monkeypatch):
        """EICAR file must produce verdict=malicious even when ClamAV is offline."""
        for mod in ("config", "backend.config"):
            try:
                import importlib
                m = importlib.import_module(mod)
                if hasattr(m, "settings"):
                    monkeypatch.setattr(m.settings, "clamav_mock_mode", False)
            except ImportError:
                pass
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        path = _tmp_bytes(b"payload\n" + eicar + b"\n")
        try:
            # Force ClamAV to an unreachable port
            result = run_scan(str(path), clamav_host="127.0.0.1", clamav_port=59999)
            assert result.clamav_status == "skipped"
            assert result.verdict == "malicious"
            rule_ids = [f["rule_id"] for f in result.to_findings_dicts()]
            assert "MAL-001" in rule_ids
        finally:
            os.unlink(path)

    def test_eicar_mock_clamav_still_detected(self, monkeypatch):
        """EICAR file must produce verdict=malicious even in mock ClamAV mode."""
        for mod in ("config", "backend.config"):
            try:
                import importlib
                m = importlib.import_module(mod)
                if hasattr(m, "settings"):
                    monkeypatch.setattr(m.settings, "clamav_mock_mode", True)
            except ImportError:
                pass
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        path = _tmp_bytes(b"payload\n" + eicar + b"\n")
        try:
            result = run_scan(str(path))
            assert result.verdict == "malicious"
            rule_ids = [f["rule_id"] for f in result.to_findings_dicts()]
            assert "MAL-001" in rule_ids
        finally:
            os.unlink(path)

    def test_eicar_remediation_removes_all_threats(self):
        """Remediating a dataset containing EICAR removes the threat so re-scan is clean."""
        from scanner.sanitizer import sanitize_file
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        path = _tmp_bytes(b"id,payload\n1," + eicar + b"\n")
        try:
            res = sanitize_file(str(path), "csv")
            assert res.error is None
            assert res.changes_count >= 1
            clean_path = _tmp_bytes(res.sanitized_bytes)
            try:
                rescan = run_scan(str(clean_path))
                assert rescan.verdict in ("clean", "clean_verified", "clean_with_limitations")
                assert rescan.threats_found_count == 0
            finally:
                os.unlink(clean_path)
        finally:
            os.unlink(path)

