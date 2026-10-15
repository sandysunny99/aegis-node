"""
Core truth fixes from Phase A (INTEGRATION_GAPS.md #1-#4, #16).

A dataset may only be stored as "clean" when the scan proved it clean
(verdict clean_verified). Anything less keeps its own status.
"""

import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from services.av_providers.base import AVScanResult

client = TestClient(app, raise_server_exceptions=False)

CLEAN_CSV = b"id,name,age\n1,Alice,25\n2,Bob,31\n"


class _AvailableCleanAV:
    """Stands in for a reachable ClamAV that finds nothing."""

    provider_name = "clamav_rest"
    provider_authority = "local_deterministic"
    mock_mode = False

    def ping(self) -> bool:
        return True

    def get_version(self) -> str:
        return "ClamAV test double"

    def scan_file(self, path: str) -> AVScanResult:
        return AVScanResult(available=True, infected=False, virus_name=None, raw_response="", error=None)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


class _UnreachableAV(_AvailableCleanAV):
    """Stands in for a ClamAV service that cannot be reached."""

    def ping(self) -> bool:
        return False

    def scan_file(self, path: str) -> AVScanResult:
        return AVScanResult(available=False, infected=False, virus_name=None, raw_response="", error="offline")


@pytest.fixture
def av_available(monkeypatch):
    monkeypatch.setattr("scanner.engine.get_av_provider", lambda: _AvailableCleanAV())


@pytest.fixture
def av_unavailable(monkeypatch):
    monkeypatch.setattr("scanner.engine.get_av_provider", lambda: _UnreachableAV())


def _upload(payload: bytes, name: str = "data.csv") -> str:
    res = client.post("/api/v1/datasets/upload", files={"file": (name, payload, "text/csv")})
    assert res.status_code == 201, res.text
    return res.json()["dataset_id"]


def _status(ds_id: str) -> str:
    return client.get(f"/api/v1/datasets/{ds_id}").json()["status"]


# ─── #1 dataset status mapping ────────────────────────────────────────────────

def test_clean_verified_scan_is_stored_as_clean(av_available):
    ds_id = _upload(CLEAN_CSV)
    res = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert res.status_code == 200, res.text
    assert res.json()["verdict"] == "clean_verified", res.json()["verification_limitations"]
    assert _status(ds_id) == "clean"


def test_clean_with_limitations_is_not_stored_as_clean(av_unavailable):
    """With ClamAV unreachable the best possible verdict is clean_with_limitations."""
    ds_id = _upload(CLEAN_CSV)
    res = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert res.json()["verdict"] == "clean_with_limitations"
    assert "CLAMAV_UNAVAILABLE" in res.json()["verification_limitations"]
    assert _status(ds_id) == "clean_limited"


def test_incomplete_scan_is_not_stored_as_clean(av_unavailable):
    ds_id = _upload(b'[\n  {"id": 1, "name": "Alice"},\n  {"id": 2, "name":', "broken.json")
    res = client.post(f"/api/v1/datasets/{ds_id}/scan")
    assert res.json()["verdict"] == "scan_incomplete"
    assert _status(ds_id) == "incomplete"


def test_history_reports_the_new_status(av_unavailable):
    ds_id = _upload(CLEAN_CSV)
    client.post(f"/api/v1/datasets/{ds_id}/scan")
    items = client.get("/api/v1/history").json()["items"]
    row = next(i for i in items if i["dataset_id"] == ds_id)
    assert row["status"] == "clean_limited"
    assert row["verdict"] == "clean_with_limitations"


# ─── #2 remediated re-scan (audit C1, kept through the merge) ────────────────
# Covered by tests/test_scan_status.py::test_rescan_of_remediated_dataset_is_rejected_without_changing_status;
# the unverified variant is below.


# ─── #3 remediation is only "completed" when the re-scan verifies it ─────────

FORMULA_CSV = b'name,val\nalice,=CMD("calc.exe")\nbob,2\n'


def _scan_and_remediate(payload: bytes = FORMULA_CSV) -> tuple[str, dict]:
    ds_id = _upload(payload)
    assert client.post(f"/api/v1/datasets/{ds_id}/scan").json()["verdict"] == "suspicious"
    res = client.post(f"/api/v1/datasets/{ds_id}/remediate")
    assert res.status_code == 200, res.text
    return ds_id, res.json()


def test_remediation_verified_by_full_rescan_is_completed(av_available):
    ds_id, rem = _scan_and_remediate()
    assert rem["remediation_status"] == "completed", rem
    assert rem["rescan_verdict"] == "clean_verified"
    assert _status(ds_id) == "remediated"


def test_remediation_without_clamav_is_unverified(av_unavailable):
    ds_id, rem = _scan_and_remediate()
    assert rem["remaining_findings_count"] == 0
    assert rem["remediation_status"] == "unverified"
    assert rem["rescan_verdict"] == "clean_with_limitations"
    assert "CLAMAV_UNAVAILABLE" in rem["rescan_limitations"]
    assert _status(ds_id) == "remediated_unverified"

    again = client.get(f"/api/v1/datasets/{ds_id}/remediation").json()
    assert again["remediation_status"] == "unverified"
    assert again["rescan_verdict"] == "clean_with_limitations"


def test_rescan_of_unverified_remediation_is_rejected_without_changing_status(av_unavailable):
    ds_id, _ = _scan_and_remediate()
    assert client.post(f"/api/v1/datasets/{ds_id}/scan").status_code == 409
    assert _status(ds_id) == "remediated_unverified"


def test_verification_rescan_is_stored_but_not_reported_as_the_dataset_scan(av_unavailable):
    from database import SessionLocal
    from models import DatasetRecord

    ds_id, rem = _scan_and_remediate()
    report = client.get(f"/api/v1/datasets/{ds_id}/report").json()
    assert report["verdict"] == "suspicious"  # still the original file's scan

    with SessionLocal() as db:
        record = db.query(DatasetRecord).filter_by(public_id=ds_id).one()
        targets = sorted(r.scan_target for r in record.scan_reports)
        assert targets == ["original", "sanitized"]
        rescan = next(r for r in record.scan_reports if r.scan_target == "sanitized")
        assert record.remediations[0].rescan_report_id == rescan.id
        assert rescan.verdict == rem["rescan_verdict"]

    row = next(i for i in client.get("/api/v1/history").json()["items"] if i["dataset_id"] == ds_id)
    assert row["scans_count"] == 1
    assert row["verdict"] == "suspicious"
