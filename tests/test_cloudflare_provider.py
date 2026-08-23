"""
Tests for Cloudflare Workers AI Provider and fallback integration.
"""

from unittest.mock import MagicMock, patch
import pytest
from services.ai_providers.cloudflare_provider import call_cloudflare
from services.llm_service import _call_cloudflare, _build_provider_chain, analyse


def test_cloudflare_provider_missing_credentials():
    """Missing token or account ID returns immediate error without network calls."""
    text, err = call_cloudflare("sys", "user", api_token="", account_id="")
    assert text is None
    assert "empty" in err


def test_cloudflare_provider_successful_call():
    """Mock successful response from Cloudflare Workers AI."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "result": {
            "response": '{"verdict": "clean", "severity": "low", "confidence": 0.95, "summary": "Dataset is safe", "evidence": [], "recommendations": [], "limitations": []}'
        },
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        text, err = call_cloudflare("sys", "user", api_token="test-token", account_id="test-account")
        assert err is None
        assert text is not None
        assert "clean" in text


def test_call_cloudflare_llm_service_integration():
    """Test _call_cloudflare parser and output sanitization."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "success": True,
        "result": {
            "response": '{"verdict": "suspicious", "severity": "medium", "confidence": 0.85, "summary": "Formula detected", "evidence": ["formula_col"], "recommendations": ["Sanitize formulas"], "limitations": []}'
        },
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res = _call_cloudflare("sys", "user", api_token="test-token", account_id="test-account")
        assert res.status == "completed"
        assert res.verdict == "suspicious"
        assert res.confidence == 0.85
        assert "cloudflare" in res.model_name


def test_cloudflare_in_provider_chain():
    """Verify cloudflare is recognized in _build_provider_chain."""
    cfg = MagicMock()
    cfg.ai_provider = "gemini"
    cfg.ai_fallback_chain = "cloudflare,groq"
    chain = _build_provider_chain(cfg)
    assert chain == [("gemini", False), ("cloudflare", True), ("groq", True)]
