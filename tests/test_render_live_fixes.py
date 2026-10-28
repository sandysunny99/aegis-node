"""Fixes found on the live Render service (24 Oct 2026)."""

import pytest
from config import settings
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from services.provider_registry import _is_configured

client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def test_health_probe_is_never_rate_limited(monkeypatch):
    """Render's health check got 429 from the per-IP limit on /health."""
    from limiter import limiter

    monkeypatch.setattr(limiter, "enabled", True)
    limiter.reset()
    codes = {client.get("/health").status_code for _ in range(70)}
    limiter.reset()
    assert codes == {200}


def test_page_shell_is_not_rate_limited(monkeypatch):
    from limiter import limiter
    from main import _STATIC_DIR

    if not _STATIC_DIR.exists():
        pytest.skip("frontend not built into backend/static")
    monkeypatch.setattr(limiter, "enabled", True)
    limiter.reset()
    codes = {client.get("/app/history").status_code for _ in range(210)}
    limiter.reset()
    assert codes == {200}


def test_ollama_is_not_offered_in_production_on_localhost(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "ollama_base_url", "http://localhost:11434")
    assert _is_configured("ollama") is False


def test_ollama_is_offered_with_a_remote_url_or_in_development(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "ollama_base_url", "https://ollama.example.org")
    assert _is_configured("ollama") is True
    monkeypatch.setattr(settings, "app_env", "development")
    monkeypatch.setattr(settings, "ollama_base_url", "http://localhost:11434")
    assert _is_configured("ollama") is True


def _scanned_dataset() -> str:
    ds = client.post("/api/v1/datasets/upload", files={"file": ("d.csv", b"id,n\n1,a\n", "text/csv")}).json()["dataset_id"]
    client.post(f"/api/v1/datasets/{ds}/scan")
    return ds


def test_missing_analysis_is_null_when_asked_optionally():
    ds = _scanned_dataset()
    res = client.get(f"/api/v1/datasets/{ds}/analysis?optional=true")
    assert res.status_code == 200
    assert res.json() is None


def test_missing_analysis_still_404_by_default():
    ds = _scanned_dataset()
    assert client.get(f"/api/v1/datasets/{ds}/analysis").status_code == 404


def test_antivirus_event_records_why_it_did_not_run():
    ds = _scanned_dataset()
    events = client.get(f"/api/v1/datasets/{ds}/events").json()["items"]
    av = next(e for e in events if e["event_type"] == "DETECTOR_COMPLETED" and e["detail"]["detector"] == "clamav")
    assert av["detail"]["provider"]
    assert "reason" in av["detail"]


def test_scan_report_names_the_antivirus_and_its_reason(monkeypatch):
    from services.av_providers.base import AVScanResult

    class _NotFound:
        def scan_file(self, path):
            return AVScanResult(available=False, infected=False, virus_name=None, raw_response="",
                                error="METADEFENDER_HASH_NOT_FOUND")

        def ping(self):
            return True

    monkeypatch.setattr(settings, "av_provider", "metadefender")
    monkeypatch.setattr("scanner.engine.get_av_provider", lambda: _NotFound())
    ds = client.post("/api/v1/datasets/upload", files={"file": ("d.csv", b"id,n\n1,a\n", "text/csv")}).json()["dataset_id"]
    scan = client.post(f"/api/v1/datasets/{ds}/scan").json()
    assert scan["av_provider"] == "metadefender"
    assert scan["av_reason"] == "METADEFENDER_HASH_NOT_FOUND"
    report = client.get(f"/api/v1/datasets/{ds}/report").json()
    assert report["av_reason"] == "METADEFENDER_HASH_NOT_FOUND"


def test_row_cap_defaults_to_100k_and_reads_scan_max_rows(monkeypatch):
    import scanner.content_checker as cc

    assert cc._env_int("SCAN_MAX_ROWS_UNSET_FOR_TEST", 100_000) == 100_000
    monkeypatch.setenv("SCAN_MAX_ROWS_TEST", "2500")
    assert cc._env_int("SCAN_MAX_ROWS_TEST", 100_000) == 2500
    monkeypatch.setenv("SCAN_MAX_ROWS_TEST", "junk")
    assert cc._env_int("SCAN_MAX_ROWS_TEST", 100_000) == 100_000


def test_optional_antivirus_is_reported_as_off_but_never_verified(monkeypatch):
    from services.av_providers.base import AVScanResult

    class _NoResult:
        def scan_file(self, path):
            return AVScanResult(available=False, infected=False, virus_name=None, raw_response="",
                                error="METADEFENDER_HASH_NOT_FOUND")

        def ping(self):
            return True

    monkeypatch.setattr(settings, "av_required", False)
    monkeypatch.setattr("scanner.engine.get_av_provider", lambda: _NoResult())
    ds = client.post("/api/v1/datasets/upload", files={"file": ("d.csv", b"id,n\n1,a\n", "text/csv")}).json()["dataset_id"]
    scan = client.post(f"/api/v1/datasets/{ds}/scan").json()
    assert "AV_SIGNATURE_SCAN_OFF" in scan["verification_limitations"]
    assert "CLAMAV_UNAVAILABLE" not in scan["verification_limitations"]
    assert scan["verdict"] == "clean_with_limitations"


def test_signature_av_requirement_follows_the_provider(monkeypatch):
    monkeypatch.setattr(settings, "av_required", None)
    monkeypatch.setattr(settings, "av_provider", "metadefender")
    assert settings.signature_av_required() is False
    monkeypatch.setattr(settings, "av_provider", "clamav_rest")
    assert settings.signature_av_required() is True
    monkeypatch.setattr(settings, "av_required", False)
    assert settings.signature_av_required() is False
