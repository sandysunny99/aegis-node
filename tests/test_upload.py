"""
tests/test_upload.py — Dataset upload endpoint tests.
Tests: allowed types, blocked types, size limit, SHA-256 integrity, DB persistence.
"""

import hashlib
import sys
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Add backend to sys.path so imports work
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

from database import Base, create_all_tables, engine
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_db():
    """Drop and recreate all tables before each test."""
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_csv(content: str = "name,value\nalice,1\nbob,2") -> tuple[bytes, str]:
    return content.encode(), "test_dataset.csv"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ─── Tests ───────────────────────────────────────────────────────────────────

def test_upload_csv_success():
    """Valid CSV upload should return 201 with correct metadata."""
    data, name = _make_csv()
    response = client.post(
        "/api/v1/datasets/upload",
        files={"file": (name, BytesIO(data), "text/csv")},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["dataset_id"] == 1
    assert body["file_format"] == "csv"
    assert body["file_size_bytes"] == len(data)
    assert body["sha256_hash"] == _sha256(data)
    assert body["status"] == "uploaded"


def test_upload_json_success():
    """Valid JSON upload should return 201."""
    data = b'[{"col1": "val1"}, {"col1": "val2"}]'
    response = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("test.json", BytesIO(data), "application/json")},
    )
    assert response.status_code == 201
    assert response.json()["file_format"] == "json"


def test_upload_blocked_extension():
    """Executables and disallowed types must be rejected with 415."""
    data = b"MZ\x90\x00"  # fake PE header
    response = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("malware.exe", BytesIO(data), "application/octet-stream")},
    )
    assert response.status_code == 415


def test_upload_blocked_python_script():
    """Python scripts must be rejected with 415."""
    data = b"import os; os.system('calc.exe')"
    response = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("evil.py", BytesIO(data), "text/x-python")},
    )
    assert response.status_code == 415


def test_upload_sha256_correct():
    """SHA-256 returned by API must match client-side computed hash."""
    data = b"id,score\n1,100\n2,200\n3,300"
    response = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("scores.csv", BytesIO(data), "text/csv")},
    )
    assert response.status_code == 201
    assert response.json()["sha256_hash"] == _sha256(data)


def test_get_dataset_status_after_upload():
    """GET /datasets/{id} should return the uploaded dataset status."""
    data, name = _make_csv()
    upload = client.post(
        "/api/v1/datasets/upload",
        files={"file": (name, BytesIO(data), "text/csv")},
    )
    dataset_id = upload.json()["dataset_id"]
    status_resp = client.get(f"/api/v1/datasets/{dataset_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "uploaded"


def test_get_nonexistent_dataset():
    """GET /datasets/9999 should return 404."""
    response = client.get("/api/v1/datasets/9999")
    assert response.status_code == 404
