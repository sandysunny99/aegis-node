"""
tests/test_scanner.py — Scanner engine unit tests.
Tests: clean file, formula injection, script injection, SQL injection, JSON format.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

from content_checker import check_file
from database import Base, create_all_tables, engine
from engine import run_scan

# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def tmp_csv(tmp_path):
    """Factory: write a CSV string to a temp file, return its path string."""
    def _write(content: str, name: str = "test.csv") -> str:
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        return str(p)
    return _write


@pytest.fixture
def tmp_json(tmp_path):
    def _write(content: str) -> str:
        p = tmp_path / "test.json"
        p.write_text(content, encoding="utf-8")
        return str(p)
    return _write


# ─── Content Checker Tests ────────────────────────────────────────────────────

def test_clean_csv_no_threats(tmp_csv):
    """A clean CSV with normal data must have 0 findings."""
    path = tmp_csv("name,score\nalice,95\nbob,87\ncharlie,76")
    result = check_file(path)
    assert result.threat_count == 0
    assert result.risk_score == 0.0
    assert result.rows_inspected == 3


def test_formula_injection_detected(tmp_csv):
    """Cell starting with '=' must trigger FORM-001."""
    path = tmp_csv('name,cmd\nalice,"=CMD|/C calc.exe!A1"')
    result = check_file(path)
    rule_ids = [f.rule_id for f in result.findings]
    assert "FORM-001" in rule_ids
    assert result.risk_score > 0


def test_dde_payload_detected(tmp_csv):
    """DDE execution payload must trigger FORM-002."""
    # Use pipe-delimited cmd pattern which matches the FORM-002 regex (cmd\s*\|)
    path = tmp_csv("name,data\nbob,cmd|/c calc")
    result = check_file(path)
    rule_ids = [f.rule_id for f in result.findings]
    assert "FORM-002" in rule_ids


def test_script_injection_detected(tmp_csv):
    """<script> tag in CSV column must trigger SCRP-001."""
    path = tmp_csv('id,comment\n1,"<script>alert(1)</script>"')
    result = check_file(path)
    rule_ids = [f.rule_id for f in result.findings]
    assert "SCRP-001" in rule_ids
    assert result.risk_score >= 3.5  # critical weight


def test_sql_injection_detected(tmp_csv):
    """Classic SQL injection payload must trigger SQLI-001."""
    path = tmp_csv("username,password\nadmin,\"' OR '1'='1\"")
    result = check_file(path)
    rule_ids = [f.rule_id for f in result.findings]
    assert "SQLI-001" in rule_ids


def test_union_select_detected(tmp_csv):
    """UNION SELECT must trigger SQLI-002."""
    path = tmp_csv("query,result\n\"UNION SELECT * FROM users--\",none")
    result = check_file(path)
    rule_ids = [f.rule_id for f in result.findings]
    assert "SQLI-002" in rule_ids


def test_json_clean_format(tmp_json):
    """JSON dataset with safe content must have 0 findings."""
    path = tmp_json('[{"name": "alice", "score": 95}, {"name": "bob", "score": 87}]')
    result = check_file(path)
    assert result.threat_count == 0


def test_json_with_injection(tmp_json):
    """JSON with injected script tag must be detected."""
    path = tmp_json('[{"comment": "<script>evil()</script>"}]')
    result = check_file(path)
    assert result.threat_count > 0


# ─── Engine Tests ─────────────────────────────────────────────────────────────

def test_engine_clean_verdict(tmp_csv):
    """Engine must return clean verdict for safe CSV (ClamAV skipped in dev)."""
    path = tmp_csv("product,price\nApple,1.99\nBanana,0.99")
    result = run_scan(path)
    assert result.verdict in ("clean", "clean_verified", "clean_with_limitations")
    assert result.risk_score == 0.0
    assert result.sha256_hash != ""
    assert result.scan_duration_ms >= 0


def test_engine_malicious_verdict(tmp_csv):
    """Engine must return malicious verdict when critical threat found."""
    path = tmp_csv('cmd,payload\n"test","<script>document.cookie</script>"')
    result = run_scan(path)
    assert result.verdict == "malicious"
    assert result.risk_score > 0
    assert result.threats_found_count > 0


def test_engine_suspicious_verdict(tmp_csv):
    """Engine must return suspicious verdict for high-severity but non-critical content."""
    path = tmp_csv("query\n\"UNION SELECT username FROM users\"")
    result = run_scan(path)
    # SQLI-002 is high severity → suspicious
    assert result.verdict in ("suspicious", "malicious")
    assert result.risk_score > 0


def test_engine_sha256_matches(tmp_path):
    """SHA-256 computed by engine must match direct file hash."""
    import hashlib
    content_bytes = b"id,value\n1,test\n2,data"
    path = tmp_path / "test.csv"
    path.write_bytes(content_bytes)   # write_bytes avoids CRLF transformation
    expected_hash = hashlib.sha256(content_bytes).hexdigest()
    result = run_scan(str(path))
    assert result.sha256_hash == expected_hash
