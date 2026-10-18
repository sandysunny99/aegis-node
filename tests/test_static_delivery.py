"""UI delivery: large responses (the built JavaScript, API docs) are gzip-compressed."""

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_large_responses_are_gzip_compressed():
    # /openapi.json is a large JSON document available in the test environment
    res = client.get("/openapi.json", headers={"Accept-Encoding": "gzip"})
    assert res.status_code == 200
    assert res.headers.get("content-encoding") == "gzip"
