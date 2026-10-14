"""
S1 — broken access control / IDOR regression tests.

- API paths and responses use an unguessable public id, never the integer primary key.
- GET /remediation never returns the live download token (only POST /remediate does).
- In production without an API key, /history only lists ids the caller already holds.
- Legacy databases get public_id added and backfilled at startup.
"""

import re

import database
import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from sqlalchemy import create_engine, inspect, text

client = TestClient(app)

_CSV = b"name,val\nalice,=CMD(\"calc.exe\")\n"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def _upload(name: str = "acl.csv") -> str:
    res = client.post("/api/v1/datasets/upload", files={"file": (name, _CSV, "text/csv")})
    assert res.status_code == 201, res.text
    return res.json()["dataset_id"]


def _upload_scan_remediate() -> tuple[str, dict]:
    ds_id = _upload()
    assert client.post(f"/api/v1/datasets/{ds_id}/scan").status_code == 200
    res = client.post(f"/api/v1/datasets/{ds_id}/remediate")
    assert res.status_code == 200, res.text
    return ds_id, res.json()


def test_upload_returns_unguessable_public_id():
    ds_id = _upload()
    assert re.fullmatch(r"[0-9a-f]{32}", ds_id)


@pytest.mark.parametrize(
    "path",
    ["", "/report", "/remediation", "/analysis", "/download-sanitized?token=x"],
)
def test_sequential_integer_ids_are_not_addressable(path):
    _upload()
    res = client.get(f"/api/v1/datasets/1{path}")
    assert res.status_code == 404


def test_integer_id_cannot_trigger_scan():
    _upload()
    assert client.post("/api/v1/datasets/1/scan").status_code == 404


def test_get_remediation_never_returns_download_token():
    ds_id, created = _upload_scan_remediate()
    assert created["download_token"]  # POST hands the token to the uploader once

    res = client.get(f"/api/v1/datasets/{ds_id}/remediation")
    assert res.status_code == 200
    assert res.json()["download_token"] is None


def test_download_is_single_use_with_token_from_post():
    ds_id, created = _upload_scan_remediate()
    url = f"/api/v1/datasets/{ds_id}/download-sanitized"
    headers = {"Authorization": f"Bearer {created['download_token']}"}
    assert client.get(url, headers=headers).status_code == 200
    assert client.get(url, headers=headers).status_code == 403


def test_history_in_production_without_api_key_requires_ids(monkeypatch):
    mine = _upload("mine.csv")
    _upload("someone_else.csv")
    monkeypatch.setattr("routers.history.settings.app_env", "production")
    monkeypatch.setattr("routers.history.settings.api_key", "")

    assert client.get("/api/v1/history").status_code == 403

    res = client.get("/api/v1/history", params={"ids": mine})
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert [item["dataset_id"] for item in body["items"]] == [mine]


def test_legacy_database_gets_public_id_backfilled(tmp_path, monkeypatch):
    legacy = create_engine(f"sqlite:///{(tmp_path / 'legacy.db').as_posix()}")
    with legacy.begin() as conn:
        conn.execute(text("CREATE TABLE datasets (id INTEGER PRIMARY KEY, original_filename TEXT)"))
        conn.execute(text("INSERT INTO datasets (id, original_filename) VALUES (1, 'a'), (2, 'b')"))
    monkeypatch.setattr(database, "engine", legacy)

    database._migrate_dataset_public_id()
    database._migrate_dataset_public_id()  # idempotent

    with legacy.connect() as conn:
        ids = [r[0] for r in conn.execute(text("SELECT public_id FROM datasets ORDER BY id"))]
    assert len(ids) == 2 and len(set(ids)) == 2
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids)
    index_names = {ix["name"] for ix in inspect(legacy).get_indexes("datasets")}
    assert "ix_datasets_public_id" in index_names
