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


def test_public_uploads_do_not_skip_a_configured_turnstile(monkeypatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "cloudflare_turnstile_secret_key", "0x4AAAAAAA-real-looking-secret")
    monkeypatch.setattr(settings, "allow_public_uploads", True)
    assert asyncio.run(verify_turnstile_token(None)) is False
