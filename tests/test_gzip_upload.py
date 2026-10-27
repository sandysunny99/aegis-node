"""
Browser uploads arrive gzip-compressed (X-Upload-Encoding: gzip) so a hosting firewall
cannot block a dataset for the injection payloads Aegis is meant to find. The server
stores and hashes the decompressed bytes, with the same size limit.
"""

import gzip
import hashlib

import pytest
from config import settings
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app

client = TestClient(app, raise_server_exceptions=False)
SQLI = b"id,v\n1,' OR 1=1 --\n2,<script>alert(1)</script>\n"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def _post(body: bytes, name="d.csv", encoding="gzip"):
    headers = {"X-Upload-Encoding": encoding} if encoding else {}
    return client.post("/api/v1/datasets/upload", files={"file": (name, body, "application/gzip")}, headers=headers)


def test_gzip_upload_is_stored_decompressed():
    res = _post(gzip.compress(SQLI))
    assert res.status_code == 201, res.text
    body = res.json()
    assert body["file_size_bytes"] == len(SQLI)
    assert body["sha256_hash"] == hashlib.sha256(SQLI).hexdigest()
    scan = client.post(f"/api/v1/datasets/{body['dataset_id']}/scan").json()
    assert scan["verdict"] in ("suspicious", "malicious")


def test_plain_upload_still_works():
    res = client.post("/api/v1/datasets/upload", files={"file": ("d.csv", SQLI, "text/csv")})
    assert res.status_code == 201
    assert res.json()["sha256_hash"] == hashlib.sha256(SQLI).hexdigest()


def test_gzip_bomb_hits_the_size_limit(monkeypatch):
    monkeypatch.setattr(settings, "max_upload_size_mb", 1)
    bomb = gzip.compress(b"id,v\n" + b"1,a\n" * (2 * 1024 * 1024 // 4))
    assert len(bomb) < 100_000
    assert _post(bomb).status_code == 413


def test_invalid_gzip_is_rejected():
    res = _post(b"not gzip at all")
    assert res.status_code == 400
    assert "compressed" in res.json()["detail"].lower()


def test_unknown_encoding_is_rejected():
    assert _post(SQLI, encoding="br").status_code == 400


def test_gzip_does_not_hide_an_executable():
    pe = bytearray(512)
    pe[0:2] = b"MZ"
    pe[60] = 0x80
    pe[0x80:0x84] = b"PE\0\0"
    assert _post(gzip.compress(bytes(pe))).status_code == 400
