"""
Remote ClamAV over an authenticated HTTPS gateway (Render backend -> Oracle VM).

The token is sent only over HTTPS, every ClamAV call carries it, and an
unreachable or rejecting gateway makes the AV stage unavailable (so the scan is
clean_limited at best), never clean.
"""

import httpx
import pytest
from services.av_providers import clamav as clamav_module
from services.av_providers.clamav import ClamAVRestProvider

_HTTPX_CLIENT = httpx.Client
TOKEN = "t" * 48


def _provider(monkeypatch, handler, url="https://scan.example.org", token=TOKEN):
    seen: list[httpx.Request] = []

    def record(request):
        seen.append(request)
        return handler(request)

    def client_factory(**kwargs):
        return _HTTPX_CLIENT(transport=httpx.MockTransport(record), **kwargs)

    monkeypatch.setattr(clamav_module.httpx, "Client", client_factory)
    monkeypatch.setattr(clamav_module, "_last_failed_check", 0.0)
    return ClamAVRestProvider(url, api_token=token), seen


def _ok(request):
    if request.url.path.endswith("/version"):
        return httpx.Response(200, json={"success": True, "data": {"version": "ClamAV 1.5.4"}})
    return httpx.Response(200, json={"success": True, "data": {"result": [{"is_infected": False, "viruses": []}]}})


@pytest.fixture
def sample(tmp_path):
    f = tmp_path / "x.csv"
    f.write_bytes(b"a,b\n1,2\n")
    return f


def test_every_call_carries_the_bearer_token(monkeypatch, sample):
    provider, seen = _provider(monkeypatch, _ok)
    assert provider.ping() is True
    assert provider.get_version() == "ClamAV 1.5.4"
    assert provider.scan_file(str(sample)).available is True
    assert len(seen) == 3
    assert all(r.headers["Authorization"] == f"Bearer {TOKEN}" for r in seen)


def test_token_is_never_sent_over_plain_http(monkeypatch, sample):
    provider, seen = _provider(monkeypatch, _ok, url="http://scan.example.org")
    assert provider.ping() is False
    res = provider.scan_file(str(sample))
    assert res.available is False
    assert "HTTPS" in res.error
    assert seen == []


def test_local_compose_without_token_still_uses_http(monkeypatch, sample):
    provider, seen = _provider(monkeypatch, _ok, url="http://clamav-rest:3000", token="")
    assert provider.scan_file(str(sample)).available is True
    assert "Authorization" not in seen[0].headers


@pytest.mark.parametrize("code", [401, 403, 502, 503])
def test_rejected_or_failing_gateway_is_unavailable(monkeypatch, sample, code):
    provider, _ = _provider(monkeypatch, lambda r: httpx.Response(code, text="no"))
    res = provider.scan_file(str(sample))
    assert (res.available, res.infected) == (False, False)


def test_unreachable_gateway_is_unavailable(monkeypatch, sample):
    def boom(request):
        raise httpx.ConnectError("unreachable", request=request)

    provider, _ = _provider(monkeypatch, boom)
    res = provider.scan_file(str(sample))
    assert (res.available, res.infected) == (False, False)


def test_factory_passes_the_token(monkeypatch):
    from config import settings
    from services.av_providers.factory import get_av_provider

    monkeypatch.setattr(settings, "av_provider", "clamav_rest")
    monkeypatch.setattr(settings, "clamav_api_url", "https://scan.example.org")
    monkeypatch.setattr(settings, "clamav_api_token", TOKEN)
    monkeypatch.setattr(settings, "clamav_mock_mode", False)
    provider = get_av_provider()
    assert provider.api_token == TOKEN
