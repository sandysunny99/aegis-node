"""Backend — smoke test: verify FastAPI app and config load correctly."""

import importlib

from fastapi.testclient import TestClient
from main import app


def test_main_imports() -> None:
    """FastAPI app object must be importable."""
    mod = importlib.import_module("main")
    assert hasattr(mod, "app"), "main.py must expose 'app'"


def test_config_imports() -> None:
    """Settings singleton must be importable."""
    mod = importlib.import_module("config")
    assert hasattr(mod, "settings"), "config.py must expose 'settings'"
    assert mod.settings.app_port == 8000


def test_health_endpoint() -> None:
    """Health endpoint must return status='ok'."""
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
