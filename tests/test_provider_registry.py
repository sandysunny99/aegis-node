import pytest
from services.provider_registry import get_registry, get_allowed_providers, validate_provider_selection, _is_configured
from config import Settings

def test_registry_builds_correctly(monkeypatch):
    registry = get_registry()
    assert "default_mode" in registry
    assert "providers" in registry
    assert len(registry["providers"]) > 0

def test_is_configured(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "groq_api_key", "secret")
    assert _is_configured("groq") is True
    
    monkeypatch.setattr(settings, "nvidia_api_key", "")
    assert _is_configured("nvidia") is False

def test_get_allowed_providers(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "groq_api_key", "secret")
    monkeypatch.setattr(settings, "cloudflare_api_token", "")
    allowed = get_allowed_providers()
    assert "groq" in allowed
    assert "cloudflare" not in allowed

def test_validate_provider_selection_rejects_unknown(monkeypatch):
    assert validate_provider_selection("nonexistent") is False

def test_validate_provider_selection_accepts_known(monkeypatch):
    from config import settings
    monkeypatch.setattr(settings, "groq_api_key", "secret")
    assert validate_provider_selection("groq") is True

