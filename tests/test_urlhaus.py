import pytest
import httpx
from unittest.mock import AsyncMock, MagicMock, patch

from backend.services.threat_intelligence.urlhaus import lookup_url, _CACHE, _normalize_url

@pytest.fixture(autouse=True)
def clear_cache():
    _CACHE.clear()

@pytest.fixture
def mock_uh_settings():
    from backend.services.threat_intelligence.urlhaus import settings
    old_enabled = settings.enable_urlhaus
    old_key = getattr(settings, 'urlhaus_auth_key', None)
    settings.enable_urlhaus = True
    settings.urlhaus_auth_key = "test_uh_key"
    settings.urlhaus_timeout_seconds = 5.0
    yield
    settings.enable_urlhaus = old_enabled
    settings.urlhaus_auth_key = old_key

@pytest.mark.asyncio
async def test_invalid_url_format(mock_uh_settings):
    res = await lookup_url("")
    assert res.status == "invalid_url"
    assert res.provider == "urlhaus"
    assert "Empty URL" in res.error_message

@pytest.mark.asyncio
async def test_missing_api_key():
    from backend.services.threat_intelligence.urlhaus import settings
    old_key = getattr(settings, 'urlhaus_auth_key', None)
    settings.enable_urlhaus = True
    settings.urlhaus_auth_key = ""
    res = await lookup_url("http://example.com")
    assert res.status == "unconfigured"
    settings.urlhaus_auth_key = old_key

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_successful_malicious_result(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download",
        "tags": ["emotet", "payload"],
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/"
    }
    mock_post.return_value = mock_response
    
    url = "http://badguy.com/payload.exe"
    res = await lookup_url(url)
    
    assert res.status == "malicious"
    assert res.malicious_count == 1
    assert "emotet" in res.tags
    assert res.indicator == url
    assert res.raw_reference == "https://urlhaus.abuse.ch/url/123/"
    
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    
    # Verify ONLY URLhaus API is called
    assert args[0] == "https://urlhaus-api.abuse.ch/v1/url/"
    assert kwargs["headers"]["Auth-Key"] == "test_uh_key"
    assert kwargs["data"]["url"] == _normalize_url(url)
    
    # 17, 18, & Security Test: Provably assert it didn't call the extracted URL
    assert "badguy.com" not in args[0]

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_successful_clean_result(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "url_status": "offline",
        "threat": "unknown"
    }
    mock_post.return_value = mock_response
    
    res = await lookup_url("http://goodguy.com")
    assert res.status == "clean"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_not_found(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "no_results"
    }
    mock_post.return_value = mock_response
    
    res = await lookup_url("http://unknown.com")
    assert res.status == "not_found"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_rate_limited(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 429
    mock_post.return_value = mock_response
    
    res = await lookup_url("http://ratelimited.com")
    assert res.status == "rate_limited"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_unauthorized_and_forbidden(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 401
    mock_post.return_value = mock_response
    
    res = await lookup_url("http://unauth.com")
    assert res.status == "unauthorized"

    mock_response.status_code = 403
    res2 = await lookup_url("http://forbidden.com")
    assert res2.status == "forbidden"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_network_timeout(mock_post, mock_uh_settings):
    mock_post.side_effect = httpx.TimeoutException("Timeout")
    
    res = await lookup_url("http://timeout.com")
    assert res.status == "timeout"
    assert "Request timed out" in res.error_message

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_5xx_error(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = httpx.HTTPStatusError("500", request=MagicMock(), response=mock_response)
    mock_post.return_value = mock_response
    
    res = await lookup_url("http://500.com")
    assert res.status == "provider_error"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_malformed_response(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    # dict missing query_status entirely
    mock_response.json.return_value = {}
    mock_post.return_value = mock_response
    
    res = await lookup_url("http://malformed.com")
    assert res.status == "provider_error"
    assert "Unexpected query_status" in res.error_message

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_cache_behavior_and_isolation(mock_post, mock_uh_settings):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "query_status": "ok",
        "url_status": "online",
        "threat": "malware_download"
    }
    mock_post.return_value = mock_response
    
    url1 = "http://testcache.com"
    
    # First call hits API
    res1 = await lookup_url(url1)
    assert mock_post.call_count == 1
    assert res1.status == "malicious"
    
    # Second call hits cache
    res2 = await lookup_url(url1)
    assert mock_post.call_count == 1
    assert res1 is res2
    
    # Call to a different URL misses cache (cache isolation)
    url2 = "http://different.com"
    res3 = await lookup_url(url2)
    assert mock_post.call_count == 2
    assert res3.status == "malicious"

@pytest.mark.asyncio
@patch("httpx.AsyncClient.post")
async def test_ssrf_boundary_attacker_url(mock_post, mock_uh_settings):
    """
    CRITICAL SECURITY TEST: Asserts that an attacker-controlled URL
    NEVER results in an HTTP request to that URL directly.
    """
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_post.return_value = mock_response
    
    malicious_url = "http://internal-metadata-server.local/latest/meta-data/"
    res = await lookup_url(malicious_url)
    
    mock_post.assert_called_once()
    args, kwargs = mock_post.call_args
    # Verify the request destination was STRICTLY URLhaus API
    assert args[0] == "https://urlhaus-api.abuse.ch/v1/url/"
    # Verify the attacker URL is strictly inside the POST data body payload
    assert kwargs["data"]["url"] == malicious_url

def test_url_normalization():
    assert _normalize_url(" http://example.com/ ") == "http://example.com/"
    assert _normalize_url("HTTP://Example.COM/Path") == "http://example.com/Path"
    assert _normalize_url("https://example.com/#fragment") == "https://example.com/"
    assert _normalize_url("https://example.com/?q=1") == "https://example.com/?q=1"
