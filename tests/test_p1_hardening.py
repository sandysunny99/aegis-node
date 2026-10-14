"""P1 regressions: S6 spoofable client IP, S8 cheap /health, C6 version, C9 compose
default, R8/F821 undefined logger in file_service."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import main
import pytest
from fastapi.testclient import TestClient
from limiter import get_client_ip
from version import APP_VERSION

client = TestClient(main.app)
REPO_ROOT = Path(__file__).resolve().parent.parent


def _request(peer: str, headers: dict) -> SimpleNamespace:
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers)


# ─── S6 ──────────────────────────────────────────────────────────────────────

def test_proxy_headers_ignored_from_untrusted_peer():
    req = _request("203.0.113.9", {"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"})
    assert get_client_ip(req) == "203.0.113.9"


def test_cf_connecting_ip_honoured_from_trusted_proxy():
    req = _request("127.0.0.1", {"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "5.6.7.8"})
    assert get_client_ip(req) == "1.2.3.4"


def test_upload_does_not_pass_spoofed_ip_to_turnstile(monkeypatch):
    verify = AsyncMock(return_value=True)
    monkeypatch.setattr("routers.datasets.verify_turnstile_token", verify)
    res = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("a.csv", b"a,b\n1,2\n", "text/csv")},
        headers={"cf-connecting-ip": "9.9.9.9"},
    )
    assert res.status_code == 201, res.text
    assert verify.await_args.kwargs["remote_ip"] == "testclient"


# ─── S8 / C6 ─────────────────────────────────────────────────────────────────

@pytest.fixture
def probe_counter(monkeypatch):
    calls = []

    def fake_probe():
        calls.append(1)
        return {
            "av_provider": "fake", "av_authority": "test", "av_available": True,
            "av_version": "x", "av_mock_mode": True,
        }

    monkeypatch.setattr(main, "_probe_av", fake_probe)
    monkeypatch.setitem(main._av_status_cache, "checked_at", None)
    return calls


def test_public_health_uses_cached_av_status(probe_counter):
    for _ in range(5):
        assert client.get("/health").status_code == 200
    assert len(probe_counter) == 1


def test_diagnostics_probes_av_live(probe_counter):
    client.get("/health")
    client.get("/health/diagnostics")
    assert len(probe_counter) == 2


def test_single_version_source(probe_counter):
    assert main.app.version == APP_VERSION
    assert client.get("/health").json()["version"] == APP_VERSION


# ─── R8 / F821 ───────────────────────────────────────────────────────────────

def test_storage_failure_raises_value_error_not_name_error(monkeypatch):
    from services import file_service as fs
    from services.storage import StorageError

    def fail(*_args, **_kwargs):
        raise StorageError("backend down")

    monkeypatch.setattr(fs.storage_backend, "save_sanitized", fail)
    with pytest.raises(ValueError, match="STORAGE_UPLOAD_FAILED"):
        fs.file_service.save_sanitized("abc.csv", b"x")


# ─── C9 ──────────────────────────────────────────────────────────────────────

def test_compose_freellmapi_defaults_off():
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert "FREELLMAPI_ENABLED=${FREELLMAPI_ENABLED:-false}" in compose
