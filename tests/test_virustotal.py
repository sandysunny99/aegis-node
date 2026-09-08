import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from backend.services.threat_intelligence.virustotal import lookup_file_hash, _CACHE

@pytest.fixture(autouse=True)
def clear_cache():
    _CACHE.clear()
    
@pytest.fixture
def mock_vt_settings():
    from backend.services.threat_intelligence.virustotal import settings
    old_enabled = settings.enable_virustotal
    old_key = settings.virustotal_api_key
    settings.enable_virustotal = True
    settings.virustotal_api_key = "test_key"
    settings.virustotal_timeout_seconds = 5.0
    yield
    settings.enable_virustotal = old_enabled
    settings.virustotal_api_key = old_key

@pytest.mark.asyncio
async def test_invalid_hash_format(mock_vt_settings):
    res = await lookup_file_hash("invalid-hash")
    assert res.status == "invalid_hash"
    assert res.provider == "virustotal"
    assert "Invalid SHA-256" in res.error_message

@pytest.mark.asyncio
async def test_missing_api_key():
    from backend.services.threat_intelligence.virustotal import settings
    old_key = settings.virustotal_api_key
    settings.enable_virustotal = True
    settings.virustotal_api_key = ""
    res = await lookup_file_hash("a" * 64)
    assert res.status == "unconfigured"
    settings.virustotal_api_key = old_key

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_successful_malicious_result(mock_get, mock_vt_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 15,
                    "suspicious": 2,
                    "harmless": 50,
                    "undetected": 10
                },
                "popular_threat_classification": {
                    "suggested_threat_label": "trojan.emotet"
                }
            }
        }
    }
    mock_get.return_value = mock_response
    
    sha256 = "b" * 64
    res = await lookup_file_hash(sha256)
    
    assert res.status == "malicious"
    assert res.malicious_count == 15
    assert res.suspicious_count == 2
    assert res.confidence == "15/77"
    assert "trojan.emotet" in res.tags
    assert res.raw_reference == f"https://www.virustotal.com/gui/file/{sha256}"
    
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    # Verify ONLY hash is sent, no file upload
    assert f"/{sha256}" in args[0]
    assert kwargs["headers"]["x-apikey"] == "test_key"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_successful_clean_result(mock_get, mock_vt_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 5}}}
    }
    mock_get.return_value = mock_response
    
    res = await lookup_file_hash("c" * 64)
    assert res.status == "clean"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_not_found(mock_get, mock_vt_settings):
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_get.return_value = mock_response
    
    res = await lookup_file_hash("d" * 64)
    assert res.status == "not_found"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_rate_limited(mock_get, mock_vt_settings):
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_get.return_value = mock_response
    
    res = await lookup_file_hash("e" * 64)
    assert res.status == "rate_limited"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_unauthorized(mock_get, mock_vt_settings):
    mock_response = MagicMock()
    mock_response.status_code = 403
    mock_get.return_value = mock_response
    
    res = await lookup_file_hash("f" * 64)
    assert res.status == "unauthorized"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_network_timeout(mock_get, mock_vt_settings):
    mock_get.side_effect = httpx.TimeoutException("Timeout")
    
    res = await lookup_file_hash("1" * 64)
    assert res.status == "timeout"
    assert "Request timed out" in res.error_message

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_cache_behavior(mock_get, mock_vt_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 10, "suspicious": 0, "harmless": 0, "undetected": 0}}}
    }
    mock_get.return_value = mock_response
    
    sha256 = "2" * 64
    
    # First call hits API
    res1 = await lookup_file_hash(sha256)
    assert mock_get.call_count == 1
    assert res1.status == "malicious"
    
    # Second call returns cached result
    res2 = await lookup_file_hash(sha256)
    assert mock_get.call_count == 1
    assert res2.status == "malicious"
    assert res1 is res2
    
    # Different hash misses cache
    res3 = await lookup_file_hash("3" * 64)
    assert mock_get.call_count == 2
