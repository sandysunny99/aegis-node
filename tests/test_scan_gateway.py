"""
Oracle scan gateway (deploy/oracle-clamav/gateway): authentication, size and rate
limits, no open-proxy behaviour, and honest errors when ClamAV is down.
"""

import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "deploy" / "oracle-clamav" / "gateway"))
from app import GatewaySettings, create_app  # noqa: E402

TOKEN = "g" * 48
CLEAN = {"success": True, "data": {"result": [{"name": "upload.bin", "is_infected": False, "viruses": []}]}}


def _gateway(upstream=None, **env):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if upstream:
            return upstream(request)
        if request.url.path.endswith("/version"):
            return httpx.Response(200, json={"success": True, "data": {"version": "ClamAV 1.5.4/28153"}})
        return httpx.Response(200, json=CLEAN)

    cfg = GatewaySettings({"SCAN_GATEWAY_TOKEN": TOKEN, "MAX_UPLOAD_MB": "1", **env})
    return TestClient(create_app(cfg, transport=httpx.MockTransport(handler))), seen


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _scan(client, payload=b"a,b\n1,2\n", headers=AUTH):
    return client.post("/api/v1/scan", files={"FILES": ("data.csv", payload)}, headers=headers)


def test_short_or_missing_token_refuses_to_start():
    with pytest.raises(RuntimeError):
        GatewaySettings({"SCAN_GATEWAY_TOKEN": "short"})
    with pytest.raises(RuntimeError):
        GatewaySettings({})


def test_health_needs_no_auth_and_reveals_nothing():
    client, seen = _gateway()
    res = client.get("/healthz")
    assert res.json() == {"status": "ok"}
    assert seen == []


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": TOKEN}])
def test_scan_and_version_reject_bad_credentials(headers):
    client, seen = _gateway()
    assert _scan(client, headers=headers).status_code == 401
    assert client.get("/api/v1/version", headers=headers).status_code == 401
    assert seen == []


def test_authorized_scan_is_forwarded_without_the_original_filename_or_token():
    client, seen = _gateway()
    res = _scan(client)
    assert res.status_code == 200 and res.json() == CLEAN
    [upstream] = seen
    assert upstream.url.path == "/api/v1/scan"
    assert b"data.csv" not in upstream.content
    assert "authorization" not in {k.lower() for k in upstream.headers}


def test_version_returns_the_real_upstream_version():
    client, _ = _gateway()
    assert client.get("/api/v1/version", headers=AUTH).json()["data"]["version"].startswith("ClamAV")


def test_oversized_upload_is_rejected_before_clamav():
    client, seen = _gateway()
    assert _scan(client, payload=b"x" * (2 * 1024 * 1024)).status_code == 413
    assert seen == []


def test_rate_limit_returns_429():
    client, _ = _gateway(RATE_LIMIT_PER_MINUTE="2")
    assert [_scan(client).status_code for _ in range(3)] == [200, 200, 429]


def test_clamav_down_is_503_not_clean():
    def down(request):
        raise httpx.ConnectError("refused", request=request)

    client, _ = _gateway(upstream=down)
    assert _scan(client).status_code == 503
    assert client.get("/api/v1/version", headers=AUTH).status_code == 503


def test_no_open_proxy_routes():
    client, seen = _gateway()
    for path in ("/", "/api/v1/../../etc/passwd", "/api/v2/scan", "/docs", "/openapi.json"):
        assert client.get(path, headers=AUTH).status_code == 404
    assert seen == []


def test_non_json_upstream_is_reported_as_failure():
    client, _ = _gateway(upstream=lambda r: httpx.Response(200, text="<html>"))
    assert _scan(client).json()["success"] is False
