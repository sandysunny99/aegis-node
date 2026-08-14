import os
from pathlib import Path
from scanner.content_checker import check_file, raw_bytes_scan, ContentFinding
from scanner.engine import run_scan
from scanner.sanitizer import sanitize_file

EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def test_eicar_raw_bytes_scan(tmp_path):
    f = tmp_path / "eicar.csv"
    f.write_bytes(b"id,payload\n1," + EICAR_BYTES + b"\n")
    findings = raw_bytes_scan(f)
    rule_ids = [x.rule_id for x in findings]
    assert "MAL-001" in rule_ids
    assert any(x.severity == "critical" for x in findings)

def test_eicar_content_checker_cell(tmp_path):
    f = tmp_path / "eicar.csv"
    f.write_bytes(b"id,payload\n1," + EICAR_BYTES + b"\n")
    res = check_file(str(f))
    rule_ids = [x.rule_id for x in res.findings]
    assert "MAL-001" in rule_ids
    assert res.threat_count >= 1

def test_eicar_engine_verdict(tmp_path):
    f = tmp_path / "eicar.csv"
    f.write_bytes(b"id,payload\n1," + EICAR_BYTES + b"\n")
    res = run_scan(str(f))
    assert res.verdict == "malicious"
    assert res.threats_found_count >= 1
    rule_ids = [x["rule_id"] for x in res.to_findings_dicts()]
    assert "MAL-001" in rule_ids

def test_eicar_remediation_and_rescan(tmp_path):
    f = tmp_path / "eicar.csv"
    f.write_bytes(b"id,payload\n1," + EICAR_BYTES + b"\n")
    san = sanitize_file(str(f), "csv")
    assert san.error is None
    assert san.changes_count >= 1
    assert any(a.rule_id == "MAL-001" for a in san.actions)

    clean_f = tmp_path / "sanitized.csv"
    clean_f.write_bytes(san.sanitized_bytes)
    rescan = run_scan(str(clean_f))
    assert rescan.verdict == "clean"
    assert rescan.threats_found_count == 0
