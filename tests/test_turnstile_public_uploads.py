"""Turnstile in production: denied without a secret, unless public uploads were opted into."""

import asyncio

from config import settings
from utils.turnstile import verify_turnstile_token


def _verify(monkeypatch, **overrides):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "cloudflare_turnstile_secret_key", "")
    for key, value in overrides.items():
        monkeypatch.setattr(settings, key, value)
    return asyncio.run(verify_turnstile_token(None))


def test_production_without_secret_denies_uploads(monkeypatch):
    assert _verify(monkeypatch, allow_public_uploads=False) is False


def test_production_with_public_uploads_allows_without_token(monkeypatch):
    assert _verify(monkeypatch, allow_public_uploads=True) is True


def test_public_uploads_switch_turnstile_off_even_with_keys_set(monkeypatch):
    """The owner's ALLOW_PUBLIC_UPLOADS=true wins over leftover Turnstile keys."""
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "cloudflare_turnstile_secret_key", "0x4AAAAAAA-real-looking-secret")
    monkeypatch.setattr(settings, "allow_public_uploads", True)
    assert asyncio.run(verify_turnstile_token(None)) is True


def test_configured_turnstile_still_enforced_without_public_uploads(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "cloudflare_turnstile_secret_key", "0x4AAAAAAA-real-looking-secret")
    monkeypatch.setattr(settings, "allow_public_uploads", False)
    assert asyncio.run(verify_turnstile_token(None)) is False


def test_health_reports_turnstile_off_when_public_uploads(monkeypatch):
    from fastapi.testclient import TestClient
    from main import app

    monkeypatch.setattr(settings, "cloudflare_turnstile_site_key", "0x4AAAAAAA-site")
    monkeypatch.setattr(settings, "cloudflare_turnstile_secret_key", "0x4AAAAAAA-real-looking-secret")
    monkeypatch.setattr(settings, "allow_public_uploads", True)
    body = TestClient(app).get("/health").json()
    assert body["turnstile_enabled"] is False
    assert body["turnstile_site_key"] == ""
    assert body["public_uploads"] is True
