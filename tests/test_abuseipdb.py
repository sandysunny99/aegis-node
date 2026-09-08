import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from backend.services.threat_intelligence.abuseipdb import lookup_ip, _CACHE, _is_public_ip, _normalize_ip

@pytest.fixture(autouse=True)
def clear_cache():
    _CACHE.clear()

@pytest.fixture
def mock_ab_settings():
    from backend.services.threat_intelligence.abuseipdb import settings
    old_enabled = settings.enable_abuseipdb
    old_key = getattr(settings, 'abuseipdb_api_key', None)
    settings.enable_abuseipdb = True
    settings.abuseipdb_api_key = "test_ab_key"
    settings.abuseipdb_timeout_seconds = 5.0
    yield
    settings.enable_abuseipdb = old_enabled
    settings.abuseipdb_api_key = old_key

def test_ip_validation():
    # Public IPs
    assert _is_public_ip("8.8.8.8") is True
    assert _is_public_ip("1.1.1.1") is True
    assert _is_public_ip("2001:4860:4860::8888") is True
    
    # Private / Reserved / Loopback
    assert _is_public_ip("192.168.1.1") is False
    assert _is_public_ip("10.0.0.1") is False
    assert _is_public_ip("127.0.0.1") is False
    assert _is_public_ip("169.254.169.254") is False
    assert _is_public_ip("172.16.0.1") is False
    assert _is_public_ip("::1") is False
    
    # Malformed
    assert _is_public_ip("999.999.999.999") is False
    assert _is_public_ip("not.an.ip") is False
    assert _is_public_ip("") is False

def test_ip_normalization():
    assert _normalize_ip(" 8.8.8.8 ") == "8.8.8.8"
    assert _normalize_ip("2001:4860:4860:0:0:0:0:8888") == "2001:4860:4860::8888"

@pytest.mark.asyncio
async def test_invalid_ip_rejection(mock_ab_settings):
    res = await lookup_ip("192.168.1.1")
    assert res.status == "invalid_ip"
    
    res = await lookup_ip("invalid")
    assert res.status == "invalid_ip"

@pytest.mark.asyncio
async def test_missing_api_key():
    from backend.services.threat_intelligence.abuseipdb import settings
    old_key = getattr(settings, 'abuseipdb_api_key', None)
    settings.enable_abuseipdb = True
    settings.abuseipdb_api_key = ""
    res = await lookup_ip("8.8.8.8")
    assert res.status == "unconfigured"
    settings.abuseipdb_api_key = old_key

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_successful_malicious_result(mock_get, mock_ab_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "isPublic": True,
            "abuseConfidenceScore": 100,
            "totalReports": 500
        }
    }
    mock_get.return_value = mock_response
    
    res = await lookup_ip("8.8.8.8")
    
    assert res.status == "malicious"
    assert res.malicious_count == 500
    assert res.confidence == "score:100"
    
    mock_get.assert_called_once()
    args, kwargs = mock_get.call_args
    assert args[0] == "https://api.abuseipdb.com/api/v2/check"
    assert kwargs["headers"]["Key"] == "test_ab_key"
    assert kwargs["params"]["ipAddress"] == "8.8.8.8"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_successful_suspicious_result(mock_get, mock_ab_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 50,
            "totalReports": 10
        }
    }
    mock_get.return_value = mock_response
    
    res = await lookup_ip("8.8.8.8")
    assert res.status == "suspicious"
    assert res.suspicious_count == 10

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_successful_clean_result(mock_get, mock_ab_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 0,
            "totalReports": 0
        }
    }
    mock_get.return_value = mock_response
    
    res = await lookup_ip("8.8.8.8")
    assert res.status == "clean"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_rate_limited(mock_get, mock_ab_settings):
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_get.return_value = mock_response
    
    res = await lookup_ip("8.8.8.8")
    assert res.status == "rate_limited"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_unauthorized_and_forbidden(mock_get, mock_ab_settings):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_get.return_value = mock_response
    
    res = await lookup_ip("8.8.8.8")
    assert res.status == "unauthorized"

    mock_response.status_code = 403
    res2 = await lookup_ip("8.8.8.8")
    assert res2.status == "forbidden"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_network_timeout(mock_get, mock_ab_settings):
    mock_get.side_effect = httpx.TimeoutException("Timeout")
    
    res = await lookup_ip("8.8.8.8")
    assert res.status == "timeout"
    assert "Request timed out" in res.error_message

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_5xx_error(mock_get, mock_ab_settings):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_get.return_value = mock_response
    
    res = await lookup_ip("8.8.8.8")
    assert res.status == "provider_error"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.get")
async def test_cache_behavior_and_isolation(mock_get, mock_ab_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "abuseConfidenceScore": 100
        }
    }
    mock_get.return_value = mock_response
    
    ip1 = "1.1.1.1"
    
    res1 = await lookup_ip(ip1)
    assert mock_get.call_count == 1
    assert res1.status == "malicious"
    
    res2 = await lookup_ip(ip1)
    assert mock_get.call_count == 1
    assert res1 is res2
    
    ip2 = "2.2.2.2"
    res3 = await lookup_ip(ip2)
    assert mock_get.call_count == 2
    assert res3.status == "malicious"
