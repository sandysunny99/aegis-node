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
