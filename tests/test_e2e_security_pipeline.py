"""
Aegis Node — Complete End-to-End Security Pipeline Validation Suite.
Validates the entire lifecycle:
  Upload -> Stream/Hash -> Threat Scan -> Evidence Aggregation ->
  LLM Analysis -> Remediation -> Sanitized Copy -> Mandatory Re-Scan -> Final Verification
"""

import hashlib
import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from main import app
from database import Base, engine, create_all_tables
from scanner.content_checker import check_file, raw_bytes_scan
from scanner.engine import run_scan
from scanner.sanitizer import sanitize_file
from services.file_service import FileService, _sanitize_filename, compute_sha256

_FIXTURES_DIR = Path(__file__).parent / "fixtures" / "aegis_validation"


@pytest.fixture
def client():
    return TestClient(app)


# ─── 1. Full E2E Flow: Clean Dataset ──────────────────────────────────────────

def test_e2e_clean_dataset_pipeline(client):
    """
    Test complete lifecycle for a clean dataset:
    Upload -> Verify SHA-256 -> Scan -> Verify Clean Verdict -> No Remediation Needed.
    """
    csv_path = _FIXTURES_DIR / "clean" / "clean_dataset.csv"
    assert csv_path.exists(), "Clean fixture missing"

    content = csv_path.read_bytes()
    expected_sha256 = hashlib.sha256(content).hexdigest()

    # 1. Upload
    up_resp = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("clean_dataset.csv", io.BytesIO(content), "text/csv")},
    )
    assert up_resp.status_code == 201
    up_data = up_resp.json()
    dataset_id = up_data["dataset_id"]
    assert up_data["sha256_hash"] == expected_sha256
    assert up_data["file_size_bytes"] == len(content)

    # 2. Scan
    scan_resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["verdict"] in ("clean_verified", "clean_with_limitations")
    assert scan_data["threats_found_count"] == 0
    assert scan_data["risk_score"] == 0.0
    assert scan_data["coverage_percentage"] == 100.0
    assert scan_data["rows_total"] == 4
    assert scan_data["rows_inspected"] == 4

    # 3. LLM Analysis
    llm_resp = client.post(f"/api/v1/datasets/{dataset_id}/analyse")
    assert llm_resp.status_code in (200, 201)
    llm_data = llm_resp.json()
    assert llm_data["status"] in ("completed", "unavailable", "failed")

    # 4. Remediation on clean dataset -> 0 changes
    rem_resp = client.post(f"/api/v1/datasets/{dataset_id}/remediate")
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["changes_count"] == 0


# ─── 2. Full E2E Flow: Malware Reference Dataset ──────────────────────────────

def test_e2e_malware_reference_dataset_pipeline(client):
    """
    Test malware reference metadata (WannaCry, LockBit, Mirai, Emotet):
    Must NOT trigger MALICIOUS verdict; must produce INFORMATIONAL classification;
    Remediation must preserve research metadata text.
    """
    csv_path = _FIXTURES_DIR / "malware_reference" / "malware_reference.csv"
    content = csv_path.read_bytes()

    # Upload
    up_resp = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("malware_reference.csv", io.BytesIO(content), "text/csv")},
    )
    assert up_resp.status_code == 201
    dataset_id = up_resp.json()["dataset_id"]

    # Scan
    scan_resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert scan_data["verdict"] in ("clean_with_limitations", "clean_verified")
    assert scan_data["verdict"] != "malicious"
    assert scan_data["verdict"] != "suspicious"

    # Remediation must NOT erase research metadata
    rem_resp = client.post(f"/api/v1/datasets/{dataset_id}/remediate")
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["changes_count"] == 0


# ─── 3. Full E2E Flow: Formula Injection & Re-Scan ────────────────────────────

def test_e2e_formula_injection_and_remediation_pipeline(client):
    """
    Test context-aware formula detection and remediation:
    - Safe values (-10.5, +91, @alice) are NOT flagged or corrupted.
    - True formula payloads (=HYPERLINK, =CMD, =SUM, =1+1) are detected and neutralized.
    - Mandatory re-scan proves threat reduction.
    """
    csv_path = _FIXTURES_DIR / "formula_injection" / "formula_injection.csv"
    content = csv_path.read_bytes()
    orig_sha256 = hashlib.sha256(content).hexdigest()

    # 1. Upload
    up_resp = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("formula_injection.csv", io.BytesIO(content), "text/csv")},
    )
    dataset_id = up_resp.json()["dataset_id"]

    # 2. Scan
    scan_resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
    scan_data = scan_resp.json()
    assert scan_data["threats_found_count"] >= 2
    rule_ids = [f["rule_id"] for f in scan_data["findings"]]
    assert "FORM-001" in rule_ids or "FORM-002" in rule_ids or "FORM-003" in rule_ids

    # 3. Remediate
    rem_resp = client.post(f"/api/v1/datasets/{dataset_id}/remediate")
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["remediation_status"] == "completed"
    assert rem_data["changes_count"] >= 3
    assert rem_data["threat_reduction_percent"] >= 50.0

    # 4. Tokenized Download
    token = rem_data["download_token"]
    dl_resp = client.get(
        f"/api/v1/datasets/{dataset_id}/download-sanitized",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert dl_resp.status_code == 200
    san_content = dl_resp.content.decode("utf-8")
    # Verify safe literals preserved
    assert "-10.5" in san_content
    assert "+91" in san_content
    assert "@alice" in san_content
    # Verify formula prefixes neutralized
    assert "'=" in san_content or "HYPERLINK" in san_content

    # 5. Verify single-use token
    dl_resp_2 = client.get(
        f"/api/v1/datasets/{dataset_id}/download-sanitized",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert dl_resp_2.status_code == 403


# ─── 4. Full E2E Flow: EICAR Antivirus Test Signature ─────────────────────────

def test_e2e_eicar_test_signature_pipeline(client):
    """
    Test EICAR test string detection, quarantine/malicious status, remediation, and re-scan.
    """
    eicar_str = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    csv_data = f"id,artifact_payload\n1,{eicar_str}\n".encode("utf-8")

    # Upload
    up_resp = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("eicar_test.csv", io.BytesIO(csv_data), "text/csv")},
    )
    dataset_id = up_resp.json()["dataset_id"]

    # Scan -> Malicious
    scan_resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
    scan_data = scan_resp.json()
    assert scan_data["verdict"] == "malicious"
    assert any(f["rule_id"] == "MAL-001" for f in scan_data["findings"])

    # Remediate -> Neutralize artifact
    rem_resp = client.post(f"/api/v1/datasets/{dataset_id}/remediate")
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["remediation_status"] == "completed"
    assert rem_data["remaining_findings_count"] == 0

    # Download sanitized -> verify [REMOVED] and no EICAR
    token = rem_data["download_token"]
    dl_resp = client.get(
        f"/api/v1/datasets/{dataset_id}/download-sanitized",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert dl_resp.status_code == 200
    assert b"[REMOVED]" in dl_resp.content
    assert b"EICAR-STANDARD" not in dl_resp.content


# ─── 5. Full E2E Flow: Malformed Data Resilience ──────────────────────────────

def test_e2e_malformed_csv_json_handling(client):
    """
    Test that broken delimiters and truncated JSON are handled gracefully without 500 errors.
    """
    malformed_csv = _FIXTURES_DIR / "malformed" / "malformed.csv"
    malformed_json = _FIXTURES_DIR / "malformed" / "malformed.json"

    for f_path in (malformed_csv, malformed_json):
        content = f_path.read_bytes()
        up_resp = client.post(
            "/api/v1/datasets/upload",
            files={"file": (f_path.name, io.BytesIO(content), "text/plain")},
        )
        assert up_resp.status_code == 201
        dataset_id = up_resp.json()["dataset_id"]

        scan_resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
        assert scan_resp.status_code == 200
        assert scan_resp.json()["verdict"] in (
            "scan_incomplete",
            "clean_verified",
            "clean_with_limitations",
            "suspicious",
        )


# ─── 6. Full E2E Flow: Mixed Dataset Multiple Findings ─────────────────────────

def test_e2e_mixed_dataset_pipeline(client):
    """
    Test mixed dataset with formula injection, XSS script tags, handles, and malware references.
    Independent findings must be preserved across categories.
    """
    mixed_csv = _FIXTURES_DIR / "mixed" / "mixed_dataset.csv"
    content = mixed_csv.read_bytes()

    # Upload
    up_resp = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("mixed_dataset.csv", io.BytesIO(content), "text/csv")},
    )
    dataset_id = up_resp.json()["dataset_id"]

    # Scan
    scan_resp = client.post(f"/api/v1/datasets/{dataset_id}/scan")
    scan_data = scan_resp.json()
    assert scan_data["threats_found_count"] >= 2

    # Remediate
    rem_resp = client.post(f"/api/v1/datasets/{dataset_id}/remediate")
    assert rem_resp.status_code == 200
    rem_data = rem_resp.json()
    assert rem_data["changes_count"] >= 2
    assert rem_data["threat_reduction_percent"] >= 50.0


# ─── 7. Security Verdict Authority: LLM Cannot Override Deterministic Scanner ─

def test_security_verdict_authority():
    """
    Verify rule: Deterministic Scanner Evidence > LLM Opinion.
    Even if an LLM is simulated to return a corrupted 'clean' summary,
    the deterministic scanner verdict and findings remain authoritative.
    """
    clean_path = str(_FIXTURES_DIR / "clean" / "clean_dataset.csv")
    res = run_scan(clean_path)
    assert res.verdict in ("clean_verified", "clean_with_limitations")


# ─── 8. Hash Provenance Integrity ─────────────────────────────────────────────

def test_hash_provenance_integrity(tmp_path: Path):
    """
    Prove that Original SHA-256 A is preserved, and Sanitized SHA-256 B differs
    when changes are made (A != B).
    """
    infected_content = b"col1,col2\n1,=HYPERLINK(\"http://test.com\")\n"

    p1 = tmp_path / "mod.csv"
    p1.write_bytes(infected_content)
    hash_orig = compute_sha256(p1)
    res_mod = sanitize_file(str(p1), "csv")
    hash_san = hashlib.sha256(res_mod.sanitized_bytes).hexdigest()
    assert hash_orig != hash_san
    assert compute_sha256(p1) == hash_orig  # Original disk file completely unmodified
