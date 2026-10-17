"""GET /health/detectors: the active profile and the real state of every detector."""

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_av_cache():
    import main

    main._av_status_cache.update(checked_at=None, value=None)
    yield
    main._av_status_cache.update(checked_at=None, value=None)


def _by_name(payload: dict) -> dict:
    return {d["name"]: d for d in payload["detectors"]}


def test_reports_profile_and_every_local_detector():
    res = client.get("/health/detectors")
    assert res.status_code == 200
    body = res.json()
    assert body["profile"] in ("lite", "full")
    names = _by_name(body)
    for name in ("clamav", "yara", "heuristics", "libmagic", "pefile", "encoding_normalization",
                 "content_rules", "virustotal", "urlhaus", "abuseipdb"):
        assert name in names, name
        assert set(names[name]) >= {"name", "layer", "enabled", "available", "version", "last_error"}


def test_disabled_detector_is_not_reported_available(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "enable_yara", False)
    yara = _by_name(client.get("/health/detectors").json())["yara"]
    assert (yara["enabled"], yara["available"]) == (False, False)


def test_unconfigured_threat_intel_is_disabled():
    names = _by_name(client.get("/health/detectors").json())
    for name in ("virustotal", "urlhaus", "abuseipdb"):
        assert names[name]["enabled"] is False


def test_lite_profile_and_storage_are_reported_honestly(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "aegis_profile", "lite")
    monkeypatch.setattr(settings, "r2_enabled", False)
    monkeypatch.setattr(settings, "clamav_mock_mode", False)
    monkeypatch.setattr(settings, "av_provider", "none")
    body = client.get("/health/detectors").json()
    assert body["profile"] == "lite"
    assert body["storage"]["backend"] == "local"
    assert _by_name(body)["clamav"]["available"] is False


def test_no_secret_values_in_the_response(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "clamav_api_token", "super-secret-gateway-token")
    monkeypatch.setattr(settings, "virustotal_api_key", "vt-secret-key")
    text = client.get("/health/detectors").text
    assert "super-secret-gateway-token" not in text
    assert "vt-secret-key" not in text
