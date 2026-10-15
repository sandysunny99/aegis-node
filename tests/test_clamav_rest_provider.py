import httpx
import pytest
from services.av_providers import clamav as clamav_module
from services.av_providers.clamav import ClamAVRestProvider

from scanner.engine import run_scan

_HTTPX_CLIENT = httpx.Client


def _mock_provider(monkeypatch, handler):
    def client_factory(**kwargs):
        return _HTTPX_CLIENT(transport=httpx.MockTransport(handler), **kwargs)

    monkeypatch.setattr(clamav_module.httpx, "Client", client_factory)
    monkeypatch.setattr(clamav_module, "_last_failed_check", 0.0)
    return ClamAVRestProvider("http://clamav-rest:3000")


def test_version_parses_nested_clamav_version(monkeypatch):
    provider = _mock_provider(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={"success": True, "data": {"version": " ClamAV 1.5.4\n"}},
        ),
    )

    assert provider.ping() is True
    assert provider.get_version() == "ClamAV 1.5.4"


@pytest.mark.parametrize(
    "payload",
    [
        {"success": True, "data": {}},
        {"success": True, "data": {"version": " \n"}},
        {"success": True, "data": {"version": 1}},
        {"success": False, "data": {"version": "ClamAV 1.5.4"}},
    ],
)
def test_invalid_version_response_is_not_ready(monkeypatch, payload):
    provider = _mock_provider(
        monkeypatch,
        lambda request: httpx.Response(200, json=payload),
    )

    assert provider.ping() is False
    assert provider.get_version() == "Unavailable"


def test_scan_sends_configured_multipart_field_and_parses_clean(monkeypatch, tmp_path):
    sample = tmp_path / "sample.csv"
    sample.write_bytes(b"name,value\nAlice,1\n")
    requests = []

    def respond(request):
        requests.append(request)
        return httpx.Response(
            200,
            json={"success": True, "data": {"result": [{"is_infected": False, "viruses": []}]}},
        )

    provider = _mock_provider(monkeypatch, respond)
    result = provider.scan_file(str(sample))

    assert len(requests) == 1
    assert requests[0].url.path == "/api/v1/scan"
    assert b'name="FILES"; filename="sample.csv"' in requests[0].content
    assert b"name,value\nAlice,1\n" in requests[0].content
    assert result.available is True
    assert result.infected is False
    assert result.error is None


def test_scan_parses_infected_result(monkeypatch, tmp_path):
    sample = tmp_path / "eicar.csv"
    sample.write_text("test", encoding="utf-8")
    provider = _mock_provider(
        monkeypatch,
        lambda request: httpx.Response(
            200,
            json={
                "success": True,
                "data": {"result": [{"is_infected": True, "viruses": [" Eicar-Test-Signature "]}]},
            },
        ),
    )

    result = provider.scan_file(str(sample))

    assert result.available is True
    assert result.infected is True
    assert result.virus_name == "Eicar-Test-Signature"


@pytest.mark.parametrize(
    "payload",
    [
        {"success": False, "message": "invalid multipart key"},
        {"success": True, "data": {}},
        {"success": True, "data": {"result": []}},
        {"success": True, "data": {"result": [{"viruses": []}]}},
        {"success": True, "data": {"result": [{"is_infected": "false", "viruses": []}]}},
        {"success": True, "data": {"result": [{"is_infected": False, "viruses": "none"}]}},
    ],
)
def test_invalid_scan_response_is_unavailable(monkeypatch, tmp_path, payload):
    sample = tmp_path / "sample.csv"
    sample.write_text("test", encoding="utf-8")
    provider = _mock_provider(
        monkeypatch,
        lambda request: httpx.Response(200, json=payload),
    )

    result = provider.scan_file(str(sample))

    assert result.available is False
    assert result.infected is False
    assert result.error


def test_scan_http_error_is_unavailable_and_preserves_response(monkeypatch, tmp_path):
    sample = tmp_path / "sample.csv"
    sample.write_text("test", encoding="utf-8")
    provider = _mock_provider(
        monkeypatch,
        lambda request: httpx.Response(400, text="The request should have only FILES key"),
    )

    result = provider.scan_file(str(sample))

    assert result.available is False
    assert result.infected is False
    assert "FILES key" in result.raw_response
    assert result.error


def test_invalid_json_response_is_unavailable(monkeypatch, tmp_path):
    sample = tmp_path / "sample.csv"
    sample.write_text("test", encoding="utf-8")
    provider = _mock_provider(
        monkeypatch,
        lambda request: httpx.Response(200, content=b"not json"),
    )

    result = provider.scan_file(str(sample))

    assert result.available is False
    assert result.infected is False
    assert result.error


def test_provider_failure_cannot_produce_clean_verified(monkeypatch, tmp_path):
    sample = tmp_path / "benign.csv"
    sample.write_text("name,value\nAlice,1\n", encoding="utf-8")
    provider = _mock_provider(
        monkeypatch,
        lambda request: httpx.Response(400, text="invalid multipart request"),
    )
    monkeypatch.setattr("scanner.engine.get_av_provider", lambda: provider)

    result = run_scan(str(sample))

    assert result.clamav_available is False
    assert result.clamav_status == "skipped"
    assert "CLAMAV_UNAVAILABLE" in result.verification_limitations
    assert result.verdict != "clean_verified"
