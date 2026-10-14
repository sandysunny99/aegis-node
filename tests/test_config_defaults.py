"""S3/S4/S5: privacy defaults and production fail-closed startup checks."""

import pytest
from config import Settings, is_turnstile_test_key
from pydantic import ValidationError

REAL_LOOKING_SITE = "0x4AAAAAAAexampleSiteKey"
REAL_LOOKING_SECRET = "0x4AAAAAAAexampleSecretKeyValue"


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


@pytest.fixture
def no_ti_env(monkeypatch):
    for name in ("ENABLE_VIRUSTOTAL", "ENABLE_URLHAUS", "ENABLE_ABUSEIPDB"):
        monkeypatch.delenv(name, raising=False)


def test_threat_intel_lookups_default_off(no_ti_env):
    cfg = _settings()
    assert cfg.enable_virustotal is False
    assert cfg.enable_urlhaus is False
    assert cfg.enable_abuseipdb is False


def test_threat_intel_fields_defined_once_with_stable_types():
    fields = Settings.model_fields
    assert fields["virustotal_timeout_seconds"].annotation is float
    assert fields["virustotal_api_key"].default is None


def test_turnstile_test_keys_detected():
    assert is_turnstile_test_key("1x0000000000000000000000000000000AA")
    assert is_turnstile_test_key("1x00000000000000000000AA")
    assert is_turnstile_test_key("3x00000000000000000000FF")
    assert not is_turnstile_test_key(REAL_LOOKING_SECRET)
    assert not is_turnstile_test_key("")


def test_production_rejects_wildcard_origins():
    with pytest.raises(ValidationError, match="ALLOWED_ORIGINS"):
        _settings(app_env="production", allowed_origins=["*"], api_key="k" * 32)


def test_production_rejects_turnstile_test_keys():
    with pytest.raises(ValidationError, match="Turnstile test keys"):
        _settings(
            app_env="production",
            allowed_origins=["https://aegis.example"],
            cloudflare_turnstile_site_key="1x00000000000000000000AA",
            cloudflare_turnstile_secret_key="1x0000000000000000000000000000000AA",
        )


def test_production_rejects_no_api_key_and_no_turnstile():
    with pytest.raises(ValidationError, match="write endpoints would be open"):
        _settings(app_env="production", allowed_origins=["https://aegis.example"])


def test_production_accepts_explicit_origins_with_turnstile():
    cfg = _settings(
        app_env="production",
        allowed_origins=["https://aegis.example"],
        cloudflare_turnstile_site_key=REAL_LOOKING_SITE,
        cloudflare_turnstile_secret_key=REAL_LOOKING_SECRET,
    )
    assert cfg.app_env == "production"


def test_development_is_not_blocked():
    cfg = _settings(app_env="development", allowed_origins=["*"])
    assert cfg.app_env == "development"
