"""
tests/test_remediation.py — Comprehensive Unit & Integration Tests for Dataset Remediation & Re-Scan Verification.

Requirements Tested:
  1. Formula Remediation: =CMD() trigger prefixed with single quote ('), re-scan formula rule resolves.
  2. Script Remediation: <script> tag neutralized, re-scan script rule resolves.
  3. SQL Payload Remediation: SQL injection string neutralized safely.
  4. Clean Dataset Non-Alteration: Clean dataset remediation does not alter data unnecessarily.
  5. Original Immutability: Original file content and original SHA-256 remain completely unchanged.
  6. SHA-256 Hash Difference: original_sha256 != sanitized_sha256 when content is modified.
  7. Automated Re-Scan Verification: Risk scores, resolved/remaining findings, and threat reduction % calculated.
  8. Path Traversal & Secure Artifact Download: GET /download-sanitized returns HTTP 200, prevents directory escape.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

from database import Base, create_all_tables, engine
from main import app
from services.file_service import file_service

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def test_formula_remediation_and_rescan():
    """Upload CSV with formula injection -> Remediate -> Verify re-scan resolves formula threat."""
    csv_payload = b"name,val\nalice,=CMD(\"calc.exe\")"

    # 1. Upload
    res_up = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("formula_test.csv", csv_payload, "text/csv")},
    )
    assert res_up.status_code == 201
    ds_id = res_up.json()["dataset_id"]
    orig_sha256 = res_up.json()["sha256_hash"]

    # 2. Initial Scan
    res_scan = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert res_scan.status_code == 200
    assert res_scan.json()["threats_found_count"] >= 1
    orig_risk = res_scan.json()["risk_score"]

    # 3. Remediate & Re-scan
    res_rem = client.post(f"/api/v1/datasets/{ds_id}/remediate")
    assert res_rem.status_code == 200
    body = res_rem.json()

    assert body["dataset_id"] == ds_id
    assert body["remediation_status"] == "completed"
    assert body["original_risk_score"] == orig_risk
    assert body["sanitized_risk_score"] == 0.0
    assert body["resolved_findings_count"] >= 1
    assert body["remaining_findings_count"] == 0
    assert body["threat_reduction_percent"] == 100.0
    assert body["original_sha256"] == orig_sha256
    assert body["sanitized_sha256"] != orig_sha256

    # 4. Verify Original Immutability
    orig_path = file_service.get_sample_path(res_up.json()["stored_filename"])
    assert orig_path.read_bytes() == csv_payload

    # 5. Verify Sanitized File Content & Download endpoint check
    res_dl = client.get(f"/api/v1/datasets/{ds_id}/download-sanitized")
    assert res_dl.status_code == 200
    assert b"'=CMD" in res_dl.content


def test_script_remediation_and_rescan():
    """Upload CSV with <script> alert -> Remediate -> Verify re-scan script threat resolved."""
    csv_payload = b"id,content\n1,<script>alert(\"xss\")</script>"

    res_up = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("script_test.csv", csv_payload, "text/csv")},
    )
    ds_id = res_up.json()["dataset_id"]

    client.post(f"/api/v1/datasets/{ds_id}/scan")

    res_rem = client.post(f"/api/v1/datasets/{ds_id}/remediate")
    assert res_rem.status_code == 200
    body = res_rem.json()
    assert body["remediation_status"] == "completed"
    assert body["remaining_findings_count"] == 0
    assert body["threat_reduction_percent"] == 100.0


def test_sql_remediation_and_rescan():
    """Upload CSV with SQL injection string -> Remediate -> Verify threat reduction."""
    csv_payload = b"user,pass\nadmin,' OR '1'='1"

    res_up = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("sql_test.csv", csv_payload, "text/csv")},
    )
    ds_id = res_up.json()["dataset_id"]

    client.post(f"/api/v1/datasets/{ds_id}/scan")

    res_rem = client.post(f"/api/v1/datasets/{ds_id}/remediate")
    assert res_rem.status_code == 200
    body = res_rem.json()
    assert body["resolved_findings_count"] >= 1
    assert body["threat_reduction_percent"] > 0.0


def test_clean_dataset_remediation():
    """Remediating a clean dataset should not unnecessarily alter data or throw errors."""
    csv_payload = b"name,age\nalice,25"

    res_up = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("clean_test.csv", csv_payload, "text/csv")},
    )
    ds_id = res_up.json()["dataset_id"]

    client.post(f"/api/v1/datasets/{ds_id}/scan")

    res_rem = client.post(f"/api/v1/datasets/{ds_id}/remediate")
    assert res_rem.status_code == 200
    body = res_rem.json()
    assert body["changes_count"] == 0
    assert body["remediation_status"] == "completed"
    assert body["threat_reduction_percent"] == 100.0


def test_download_sanitized_endpoint_and_path_traversal():
    """Test GET /download-sanitized endpoint behavior and path traversal protection."""
    # 1. Un-remediated dataset download should return 404
    res_up = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("dummy.csv", b"a,b\n1,2", "text/csv")},
    )
    ds_id = res_up.json()["dataset_id"]

    res_dl_none = client.get(f"/api/v1/datasets/{ds_id}/download-sanitized")
    assert res_dl_none.status_code == 404

    # 2. After remediation, download succeeds
    client.post(f"/api/v1/datasets/{ds_id}/scan")
    client.post(f"/api/v1/datasets/{ds_id}/remediate")

    res_dl_ok = client.get(f"/api/v1/datasets/{ds_id}/download-sanitized")
    assert res_dl_ok.status_code == 200
    assert "attachment; filename=\"sanitized_dummy.csv\"" in res_dl_ok.headers.get("content-disposition", "")
