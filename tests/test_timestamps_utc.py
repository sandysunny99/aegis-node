"""
Release check: every API timestamp carries its UTC offset. SQLite drops the timezone,
so naive values used to go out without one and browsers showed UTC times as local
time (an India-time user saw 11:08 for a scan made at 16:38).
"""

from datetime import datetime

import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def _aware(value: str) -> bool:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).utcoffset() is not None


def test_api_timestamps_are_timezone_aware():
    up = client.post("/api/v1/datasets/upload", files={"file": ("d.csv", b"id,n\n1,a\n", "text/csv")}).json()
    ds = up["dataset_id"]
    assert _aware(up["uploaded_at"])
    scan = client.post(f"/api/v1/datasets/{ds}/scan").json()
    assert _aware(scan["scanned_at"])
    assert _aware(client.get(f"/api/v1/datasets/{ds}").json()["uploaded_at"])
    assert _aware(client.get(f"/api/v1/datasets/{ds}/report").json()["scanned_at"])
    item = client.get("/api/v1/scans").json()["items"][0]
    assert _aware(item["completed_at"]) and _aware(item["started_at"])
    assert all(_aware(e["created_at"]) for e in client.get(f"/api/v1/datasets/{ds}/events").json()["items"])
    assert _aware(client.get("/api/v1/history").json()["items"][0]["uploaded_at"])
