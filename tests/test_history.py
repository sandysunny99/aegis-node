"""
tests/test_history.py — Unit & Integration tests for Scan History API.

Requirements Tested:
  - Empty history returns total=0 and empty items list.
  - Multiple scans on a dataset do not duplicate dataset records in history.
  - Pagination parameters (page, page_size max 100) are enforced.
  - History response never exposes internal filesystem paths or API credentials.
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

from database import Base, create_all_tables, engine
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def test_empty_history():
    """GET /api/v1/history when database is empty returns total=0."""
    response = client.get("/api/v1/history")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 0
    assert body["page"] == 1
    assert body["page_size"] == 20
    assert body["items"] == []


def test_history_single_dataset_scanned():
    """Upload and scan one dataset -> appears in history with correct status and risk_score."""
    # Upload
    res_up = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("dataset_a.csv", b"a,b\n1,2", "text/csv")},
    )
    ds_id = res_up.json()["dataset_id"]

    # Scan
    client.post(f"/api/v1/datasets/{ds_id}/scan")

    # History
    res_hist = client.get("/api/v1/history")
    assert res_hist.status_code == 200
    body = res_hist.json()
    assert body["total"] == 1
    item = body["items"][0]
    assert item["dataset_id"] == ds_id
    assert item["original_filename"] == "dataset_a.csv"
    assert item["scans_count"] == 1
    assert item["verdict"] in ("clean", "clean_verified", "clean_with_limitations")
    assert item["risk_score"] == 0.0

    # Ensure no file paths or secrets in response keys or values
    raw_json = res_hist.text
    assert "stored_filename" not in item
    assert "C:\\" not in raw_json
    assert "/data/samples" not in raw_json


def test_history_multiple_scans_same_dataset():
    """Scanning a dataset multiple times does not duplicate the dataset entry in history."""
    res_up = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("repeat.csv", b"col1\nval1", "text/csv")},
    )
    ds_id = res_up.json()["dataset_id"]

    # Scan twice
    client.post(f"/api/v1/datasets/{ds_id}/scan")
    client.post(f"/api/v1/datasets/{ds_id}/scan")

    res_hist = client.get("/api/v1/history")
    body = res_hist.json()
    assert body["total"] == 1
    assert body["items"][0]["scans_count"] == 2


def test_history_pagination():
    """Upload 5 datasets -> page_size=2 returns 3 pages."""
    for i in range(5):
        client.post(
            "/api/v1/datasets/upload",
            files={"file": (f"data_{i}.csv", f"id\n{i}".encode(), "text/csv")},
        )

    # Page 1
    p1 = client.get("/api/v1/history?page=1&page_size=2").json()
    assert p1["total"] == 5
    assert len(p1["items"]) == 2

    # Page 3
    p3 = client.get("/api/v1/history?page=3&page_size=2").json()
    assert p3["total"] == 5
    assert len(p3["items"]) == 1


def test_history_page_size_max_limit():
    """page_size > 100 should be rejected by Pydantic validation with 422."""
    res = client.get("/api/v1/history?page_size=200")
    assert res.status_code == 422


def test_history_requires_api_key_when_configured(monkeypatch):
    """When API key is configured, GET /history without key must return 401 (A-011)."""
    import utils.auth
    monkeypatch.setattr(utils.auth.settings, "api_key", "secret-test-key")

    # Request without key
    unauth = client.get("/api/v1/history")
    assert unauth.status_code == 401

    # Request with valid key
    auth_resp = client.get("/api/v1/history", headers={"X-API-Key": "secret-test-key"})
    assert auth_resp.status_code == 200


