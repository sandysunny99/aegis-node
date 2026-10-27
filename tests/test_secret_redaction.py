"""Provider errors must never carry a credential; keys are trimmed at load."""

from config import Settings, settings
from utils.redact import redact_secrets


def test_configured_key_and_bearer_header_are_redacted(monkeypatch):
    monkeypatch.setattr(settings, "nvidia_api_key", "nvapi-SECRETVALUE1234567890")
    msg = "nvidia: Illegal header value b'Bearer nvapi-SECRETVALUE1234567890\n'"
    out = redact_secrets(msg)
    assert "SECRETVALUE" not in out
    assert "[redacted]" in out


def test_token_shapes_are_redacted_even_when_not_configured():
    out = redact_secrets("auth failed for gsk_abcdefghijklmnop and AIzaSyAbcdefghijk123 and xai-abcdefghijklmn")
    assert "abcdefghijklmnop" not in out and "SyAbcdefghijk123" not in out and "xai-abcdefghijklmn" not in out


def test_ordinary_text_is_untouched():
    assert redact_secrets("Provider gemini unknown_provider_error (risk-score high)") == \
        "Provider gemini unknown_provider_error (risk-score high)"


def test_keys_are_trimmed_at_load(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-abc123456789\n")
    assert Settings(_env_file=None).nvidia_api_key == "nvapi-abc123456789"


def test_unavailable_analysis_never_returns_the_key(monkeypatch):
    from services.llm_service import _unavailable_result

    monkeypatch.setattr(settings, "nvidia_api_key", "nvapi-SECRETVALUE1234567890")
    res = _unavailable_result("chain_exhausted", "nvidia: Bearer nvapi-SECRETVALUE1234567890")
    assert "SECRETVALUE" not in res.error
    assert all("SECRETVALUE" not in lim for lim in res.limitations)
