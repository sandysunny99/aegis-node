"""
Scan-endpoint state machine regressions (C1, C2, C3) and bounded indicator
extraction (C4/C5).
"""

import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from services.threat_intelligence.enrichment import extract_indicators

client = TestClient(app, raise_server_exceptions=False)

EICAR_BYTES = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def _upload(payload: bytes, name: str = "data.csv") -> str:
    res = client.post("/api/v1/datasets/upload", files={"file": (name, payload, "text/csv")})
    assert res.status_code == 201, res.text
    return res.json()["dataset_id"]


def _status(ds_id: str) -> str:
    return client.get(f"/api/v1/datasets/{ds_id}").json()["status"]


def test_rescan_of_remediated_dataset_is_rejected_without_changing_status():
    """C1: previously the dataset was permanently set to 'error'."""
    ds_id = _upload(b"name,val\nalice,=CMD(\"calc.exe\")\n")
    assert client.post(f"/api/v1/datasets/{ds_id}/scan").status_code == 200
    assert client.post(f"/api/v1/datasets/{ds_id}/remediate").status_code == 200
    assert _status(ds_id) == "remediated"

    res = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert res.status_code == 409
    assert _status(ds_id) == "remediated"


def test_failure_after_scan_does_not_leave_dataset_stuck_scanning(monkeypatch):
    """C2: an exception after run_scan used to leave status='scanning' forever."""
    ds_id = _upload(b"name,val\nalice,1\n")

    async def boom(*_args, **_kwargs):
        raise RuntimeError("simulated failure after scan")

    monkeypatch.setattr("routers.datasets.enrich_scan_result", boom)
    assert client.post(f"/api/v1/datasets/{ds_id}/scan").status_code == 500
    assert _status(ds_id) == "error"

    monkeypatch.undo()
    second = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert second.status_code == 200
    # monkeypatch.undo() also drops conftest's ClamAV mock, so this rescan runs with
    # ClamAV unreachable: the honest stored status is clean_limited, not clean.
    assert _status(ds_id) == "clean_limited", second.json()["verification_limitations"]


def test_failed_rescan_keeps_last_good_status(monkeypatch):
    ds_id = _upload(b"name,val\nalice,1\n")
    assert client.post(f"/api/v1/datasets/{ds_id}/scan").status_code == 200

    def explode(*_args, **_kwargs):
        raise OSError("simulated quarantine/report failure")

    monkeypatch.setattr("routers.datasets.ScanReportRecord", explode)
    assert client.post(f"/api/v1/datasets/{ds_id}/scan").status_code == 500
    assert _status(ds_id) == "clean"


def test_quarantined_dataset_can_be_rescanned():
    """C3: the scan used the samples/ path even after the file moved to quarantine/."""
    ds_id = _upload(b"id,payload\n1," + EICAR_BYTES + b"\n", "eicar_rescan.csv")
    first = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert first.status_code == 200
    assert first.json()["verdict"] == "malicious"
    assert _status(ds_id) == "quarantined"

    second = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert second.status_code == 200, second.text
    assert second.json()["verdict"] == "malicious"
    assert _status(ds_id) == "quarantined"


def test_extract_indicators_is_bounded_ordered_and_deduplicated(tmp_path):
    rows = [f"row{i},http://host{i}.example/p,10.0.0.{i}" for i in range(20)]
    rows.insert(1, "dup,http://host0.example/p,10.0.0.0")
    f = tmp_path / "ind.csv"
    f.write_text("\n".join(rows))

    found = extract_indicators(f, limit=5)
    assert found.urls == [f"http://host{i}.example/p" for i in range(5)]
    assert found.ips == [f"10.0.0.{i}" for i in range(5)]


def test_extract_indicators_sees_values_across_chunk_boundary(tmp_path, monkeypatch):
    monkeypatch.setattr("services.threat_intelligence.enrichment._CHUNK_BYTES", 64)
    f = tmp_path / "split.csv"
    f.write_bytes(b"x" * 60 + b",http://split.example/path,192.168.1.10\n")

    found = extract_indicators(f)
    # the URL straddles the first chunk boundary: no truncated prefix may leak through
    assert found.urls == ["http://split.example/path"]
    assert found.ips == ["192.168.1.10"]


def test_extracted_url_never_includes_neighbouring_csv_cells(tmp_path):
    f = tmp_path / "cells.csv"
    f.write_text("name,link,secret\nalice,http://evil.example/x,patient-record-123\n")
    assert extract_indicators(f).urls == ["http://evil.example/x"]

