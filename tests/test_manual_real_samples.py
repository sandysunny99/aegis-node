import io
from fastapi.testclient import TestClient
from main import app
from database import Base, engine, create_all_tables

def test_real_sample_demo_clean():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    client = TestClient(app)

    with open("data/demo_clean.csv", "rb") as f:
        up = client.post("/api/v1/datasets/upload", files={"file": ("demo_clean.csv", f, "text/csv")})
    assert up.status_code == 201
    cid = up.json()["dataset_id"]

    scan = client.post(f"/api/v1/datasets/{cid}/scan")
    assert scan.status_code == 200
    res = scan.json()
    assert res["verdict"] in ("clean", "clean_verified", "clean_with_limitations")
    assert res["threats_found_count"] == 0
    assert res["risk_score"] == 0.0

def test_real_sample_demo_malicious():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    client = TestClient(app)

    with open("data/demo_malicious.csv", "rb") as f:
        up = client.post("/api/v1/datasets/upload", files={"file": ("demo_malicious.csv", f, "text/csv")})
    assert up.status_code == 201
    mid = up.json()["dataset_id"]

    scan = client.post(f"/api/v1/datasets/{mid}/scan")
    assert scan.status_code == 200
    res = scan.json()
    assert res["verdict"] in ("suspicious", "malicious")
    assert res["threats_found_count"] >= 5

    rem = client.post(f"/api/v1/datasets/{mid}/remediate")
    assert rem.status_code == 200
    rem_res = rem.json()
    assert rem_res["remediation_status"] == "completed"
    assert rem_res["remaining_findings_count"] == 0
    assert rem_res["threat_reduction_percent"] == 100.0

    # Token download
    token = rem_res["download_token"]
    dl = client.get(f"/api/v1/datasets/{mid}/download-sanitized", headers={"Authorization": f"Bearer {token}"})
    assert dl.status_code == 200
    assert len(dl.content) > 0

    # Single-use check
    dl2 = client.get(f"/api/v1/datasets/{mid}/download-sanitized", headers={"Authorization": f"Bearer {token}"})
    assert dl2.status_code == 403

def test_real_sample_eicar_file():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    client = TestClient(app)

    eicar_bytes = b"id,name,payload\n1,Test,X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"
    up = client.post("/api/v1/datasets/upload", files={"file": ("eicar_test.csv", io.BytesIO(eicar_bytes), "text/csv")})
    assert up.status_code == 201
    eid = up.json()["dataset_id"]

    scan = client.post(f"/api/v1/datasets/{eid}/scan")
    assert scan.status_code == 200
    res = scan.json()
    assert res["verdict"] == "malicious"
    rule_ids = [f["rule_id"] for f in res["findings"]]
    assert "MAL-001" in rule_ids

    rem = client.post(f"/api/v1/datasets/{eid}/remediate")
    assert rem.status_code == 200
    rem_res = rem.json()
    assert rem_res["remediation_status"] == "completed"
    assert rem_res["remaining_findings_count"] == 0
    assert rem_res["threat_reduction_percent"] == 100.0

    # Token download
    token = rem_res["download_token"]
    dl = client.get(f"/api/v1/datasets/{eid}/download-sanitized", headers={"Authorization": f"Bearer {token}"})
    assert dl.status_code == 200
    assert b"[REMOVED]" in dl.content
    assert b"EICAR" not in dl.content
