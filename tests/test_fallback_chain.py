import pytest
from unittest.mock import patch, MagicMock
from backend.services.llm_service import analyse, LlmAnalysisResult
from backend.schemas import ThreatFinding

@pytest.mark.asyncio
async def test_cloudflare_failure_mapping():
    """Verify Cloudflare API error codes map to explicit soft failure statuses."""
    from backend.services.ai_providers.cloudflare_provider import call_cloudflare
    from backend.services.llm_service import _call_cloudflare
    
    with patch("services.ai_providers.cloudflare_provider.call_cloudflare") as mock_cf, \
         patch("backend.services.llm_service.settings") as mock_settings:
        mock_settings.cloudflare_api_token = "valid"
        mock_settings.cloudflare_account_id = "valid"
        # Test 401 Unauthorized
        mock_cf.return_value = (None, "Cloudflare API authentication failed (HTTP 401)")
        res_401 = _call_cloudflare("system", "user")
        assert res_401.status == "unauthorized"

        # Test 429 Quota Exhausted
        mock_cf.return_value = (None, "Cloudflare Workers AI rate limit / neuron quota reached (HTTP 429)")
        res_429 = _call_cloudflare("system", "user")
        assert res_429.status == "quota_exhausted"
        
        # Test 5xx Unavailable
        mock_cf.return_value = (None, "Cloudflare connection error: 503")
        res_503 = _call_cloudflare("system", "user")
        assert res_503.status == "unavailable"
        
        # Test Timeout
        mock_cf.return_value = (None, "timeout during API call")
        res_timeout = _call_cloudflare("system", "user")
        assert res_timeout.status == "timeout"
        
        # Test Invalid Response
        mock_cf.return_value = ("{not json}", None)
        res_invalid = _call_cloudflare("system", "user")
        assert res_invalid.status == "invalid_response"

@pytest.mark.asyncio
async def test_fallback_chain_gemini_to_cloudflare():
    """Verify that a soft failure in Gemini triggers Cloudflare Workers AI."""
    with patch("backend.services.llm_service._call_gemini") as mock_gemini, \
         patch("backend.services.llm_service._call_cloudflare") as mock_cf, \
         patch("backend.services.llm_service.settings") as mock_settings:
         
         # Force the configuration chain
         mock_settings.ai_provider = "gemini"
         mock_settings.ai_fallback_chain = "cloudflare"
         mock_settings.gemini_api_key = "test_gemini_key"
         mock_settings.cloudflare_api_token = "test_cf_key"
         mock_settings.cloudflare_account_id = "test_cf_acct"
         
         # Setup Gemini to fail with Quota Exhausted
         mock_gemini.return_value = LlmAnalysisResult(status="quota_exhausted", model_name="gemini")
         
         # Setup Cloudflare to succeed
         mock_cf.return_value = LlmAnalysisResult(status="completed", model_name="cloudflare/llama", verdict="malicious")
         
         final_result = analyse(1, "csv", 100, "CLEAN", 0.0, [])
         
         # Assert Gemini was called
         assert mock_gemini.called
         # Assert Cloudflare was called as fallback
         assert mock_cf.called
         # Final result should be the successful Cloudflare result
         assert final_result.status == "completed"
         assert final_result.model_name == "cloudflare/llama"
         
@pytest.mark.asyncio
async def test_fallback_chain_ultimate_failure():
    """Verify that if all providers fail, a safe error is returned."""
    with patch("backend.services.llm_service._call_gemini") as mock_gemini, \
         patch("backend.services.llm_service._call_cloudflare") as mock_cf, \
         patch("backend.services.llm_service.settings") as mock_settings:
         
         # Force the configuration chain
         mock_settings.ai_provider = "gemini"
         mock_settings.ai_fallback_chain = "cloudflare"
         mock_settings.gemini_api_key = "test_gemini_key"
         mock_settings.cloudflare_api_token = "test_cf_key"
         mock_settings.cloudflare_account_id = "test_cf_acct"
         
         # Setup Gemini to fail
         mock_gemini.return_value = LlmAnalysisResult(status="timeout", model_name="gemini")
         
         # Setup Cloudflare to fail
         mock_cf.return_value = LlmAnalysisResult(status="timeout", model_name="cloudflare")
         
         final_result = analyse(1, "csv", 100, "CLEAN", 0.0, [])
         
         # Both should be called
         assert mock_gemini.called
         assert mock_cf.called
         # Final result must reflect the failure safely
         assert final_result.status in ("failed", "timeout", "unavailable")
