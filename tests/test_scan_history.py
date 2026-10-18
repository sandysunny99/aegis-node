"""
Phase C: scan history as an application feature — append-only events per dataset
and scan, scan list/detail/timeline routes with filters, and an honest persistence flag.
"""

import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from services.av_providers.base import AVScanResult

client = TestClient(app, raise_server_exceptions=False)
CLEAN = b"id,name\n1,Alice\n2,Bob\n"
FORMULA = b'name,val\nalice,=CMD("calc.exe")\nbob,2\n'


class _CleanAV:
    provider_name = "clamav_rest"
    provider_authority = "local_deterministic"
    mock_mode = False

    def ping(self):
        return True

    def get_version(self):
        return "ClamAV test"

    def scan_file(self, path):
        return AVScanResult(available=True, infected=False, virus_name=None, raw_response="", error=None)


@pytest.fixture(autouse=True)
def fresh_db(monkeypatch):
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    monkeypatch.setattr("scanner.engine.get_av_provider", lambda: _CleanAV())
    yield
    Base.metadata.drop_all(bind=engine)


def _upload(payload=CLEAN, name="d.csv"):
    res = client.post("/api/v1/datasets/upload", files={"file": (name, payload, "text/csv")})
    assert res.status_code == 201, res.text
    return res.json()["dataset_id"]


def _scan(ds):
    res = client.post(f"/api/v1/datasets/{ds}/scan")
    assert res.status_code == 200, res.text
    return res.json()


def _types(events):
    return [e["event_type"] for e in events]


# ─── events ───────────────────────────────────────────────────────────────────

def test_scan_records_upload_scan_detector_and_completion_events():
    ds = _upload()
    scan = _scan(ds)
    events = client.get(f"/api/v1/datasets/{ds}/events").json()["items"]
    types = _types(events)
    assert types[0] == "UPLOAD_ACCEPTED"
    assert "SCAN_STARTED" in types and types[-1] == "SCAN_COMPLETED"
    assert {"clamav", "yara", "heuristics", "content_rules"} <= {
        e["detail"].get("detector") for e in events if e["event_type"] == "DETECTOR_COMPLETED"}
    done = events[-1]
    assert done["scan_id"] == scan["scan_public_id"]
    assert done["detail"]["verdict"] == scan["verdict"]
    # timestamps are ordered, newest last
    assert [e["created_at"] for e in events] == sorted(e["created_at"] for e in events)


def test_threat_intel_not_configured_records_no_lookup_event():
    ds = _upload()
    _scan(ds)
    types = _types(client.get(f"/api/v1/datasets/{ds}/events").json()["items"])
    assert not [t for t in types if t.startswith("THREAT_INTEL_LOOKUP")]


def test_failed_scan_records_scan_failed(monkeypatch):
    ds = _upload()

    async def boom(*_a, **_k):
        raise RuntimeError("simulated")
    monkeypatch.setattr("routers.datasets.enrich_scan_result", boom)
    assert client.post(f"/api/v1/datasets/{ds}/scan").status_code == 500
    types = _types(client.get(f"/api/v1/datasets/{ds}/events").json()["items"])
    assert types[-1] == "SCAN_FAILED"
    assert "SCAN_COMPLETED" not in types


def test_remediation_and_verification_are_recorded():
    ds = _upload(FORMULA)
    _scan(ds)
    rem = client.post(f"/api/v1/datasets/{ds}/remediate").json()
    events = client.get(f"/api/v1/datasets/{ds}/events").json()["items"]
    types = _types(events)
    assert types.index("REMEDIATION_STARTED") < types.index("VERIFICATION_SCAN_COMPLETED") \
        < types.index("REMEDIATION_COMPLETED")
    verify = next(e for e in events if e["event_type"] == "VERIFICATION_SCAN_COMPLETED")
    assert verify["detail"]["verdict"] == rem["rescan_verdict"]
    done = next(e for e in events if e["event_type"] == "REMEDIATION_COMPLETED")
    assert done["detail"]["remediation_status"] == rem["remediation_status"]


def test_ai_analysis_is_recorded_with_its_real_outcome(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "ai_provider", "none")
    monkeypatch.setattr(settings, "ai_fallback_chain", "")
    ds = _upload()
    _scan(ds)
    client.post(f"/api/v1/datasets/{ds}/analyse")
    events = client.get(f"/api/v1/datasets/{ds}/events").json()["items"]
    started = [e for e in events if e["event_type"] == "AI_ANALYSIS_STARTED"]
    done = [e for e in events if e["event_type"] == "AI_ANALYSIS_COMPLETED"]
    assert started and done
    assert done[-1]["detail"]["status"] == "unavailable"
    assert done[-1]["detail"]["llm_invoked"] is False


def test_events_contain_no_file_contents_or_original_filename():
    ds = _upload(b"id,secret\n1,patient-record-123\n", name="private_patients.csv")
    _scan(ds)
    text = client.get(f"/api/v1/datasets/{ds}/events").text
    assert "patient-record-123" not in text
    assert "private_patients" not in text


# ─── scan list, detail, dataset scans ────────────────────────────────────────

def test_scan_list_is_newest_first_and_paginated():
    ids = [_upload(name=f"d{i}.csv") for i in range(3)]
    scans = [_scan(ds) for ds in ids]
    page1 = client.get("/api/v1/scans?page=1&page_size=2").json()
    page2 = client.get("/api/v1/scans?page=2&page_size=2").json()
    assert page1["total"] == 3
    got = [s["scan_id"] for s in page1["items"] + page2["items"]]
    assert got == [s["scan_public_id"] for s in reversed(scans)]


def test_scan_list_filters():
    clean = _upload()
    bad = _upload(FORMULA)
    _scan(clean)
    _scan(bad)
    items = client.get("/api/v1/scans?verdict=suspicious").json()["items"]
    assert [i["dataset_id"] for i in items] == [bad]
    assert client.get("/api/v1/scans?file_format=json").json()["total"] == 0
    assert client.get("/api/v1/scans?since=2999-01-01T00:00:00Z").json()["total"] == 0
    assert client.get("/api/v1/scans?enrichment_status=DISABLED").json()["total"] == 2


def test_scan_detail_and_timeline():
    ds = _upload()
    scan = _scan(ds)
    detail = client.get(f"/api/v1/scans/{scan['scan_public_id']}").json()
    assert detail["dataset_id"] == ds and detail["verdict"] == scan["verdict"]
    assert detail["target"] == "original"
    timeline = client.get(f"/api/v1/scans/{scan['scan_public_id']}/events").json()["items"]
    assert _types(timeline)[0] == "SCAN_STARTED" and _types(timeline)[-1] == "SCAN_COMPLETED"


def test_unknown_or_malformed_scan_id_is_404():
    assert client.get("/api/v1/scans/1").status_code == 404
    assert client.get(f"/api/v1/scans/{'0' * 32}").status_code == 404


def test_dataset_scans_include_the_verification_rescan():
    ds = _upload(FORMULA)
    _scan(ds)
    client.post(f"/api/v1/datasets/{ds}/remediate")
    items = client.get(f"/api/v1/datasets/{ds}/scans").json()["items"]
    assert [i["target"] for i in items] == ["sanitized", "original"]  # newest first


def test_persistence_flag_is_reported():
    body = client.get("/api/v1/scans").json()
    assert set(body["persistence"]) >= {"durable", "database", "note"}


def test_production_without_api_key_requires_dataset_ids(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "api_key", "")
    ds = _upload()
    _scan(ds)
    assert client.get("/api/v1/scans").status_code == 403
    assert client.get(f"/api/v1/scans?ids={ds}").json()["total"] == 1


# ─── persistence ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(("url", "profile", "durable"), [
    ("sqlite:////app/db/aegis_node.db", "full", True),
    ("sqlite:////tmp/aegis_node.db", "lite", False),
    ("sqlite:////tmp/aegis_node.db", "full", False),
    ("sqlite:////app/db/aegis_node.db", "lite", False),
    ("postgresql://user@host/db", "lite", True),
])
def test_persistence_flag_matches_the_storage(monkeypatch, url, profile, durable):
    from config import settings
    from services.detector_status import persistence_info

    monkeypatch.setattr(settings, "database_url", url)
    monkeypatch.setattr(settings, "aegis_profile", profile)
    assert persistence_info()["durable"] is durable


def test_history_rows_survive_a_new_database_connection(tmp_path):
    """A file-backed database keeps events after every connection is closed (a restart)."""
    import json

    from database import Base as ModelBase
    from models import ScanEventRecord
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    url = f"sqlite:///{(tmp_path / 'h.db').as_posix()}"
    first = create_engine(url)
    ModelBase.metadata.create_all(first)
    with Session(first) as s:
        s.add(ScanEventRecord(event_type="UPLOAD_ACCEPTED", detail_json=json.dumps({"x": 1})))
        s.commit()
    first.dispose()

    second = create_engine(url)
    with Session(second) as s:
        assert [e.event_type for e in s.query(ScanEventRecord).all()] == ["UPLOAD_ACCEPTED"]
    second.dispose()
