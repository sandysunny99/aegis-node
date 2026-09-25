import pytest
import time
from email.utils import formatdate
import httpx

from backend.services.llm_error_classifier import (
    classify_error, 
    parse_retry_after, 
    AegisProviderErrorType
)

class MockResponse:
    def __init__(self, status_code, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text

def test_parse_retry_after_delta_seconds():
    assert parse_retry_after("15") == 15
    assert parse_retry_after("120", max_delay=60) == 60  # clamp
    assert parse_retry_after("-5") == 0

def test_parse_retry_after_http_date():
    future_time = time.time() + 30
    http_date = formatdate(future_time, usegmt=True)
    delay = parse_retry_after(http_date)
    assert 28 <= delay <= 32  # account for slight time drift during test execution

    # Past date
    past_time = time.time() - 30
    past_http_date = formatdate(past_time, usegmt=True)
    assert parse_retry_after(past_http_date) == 0

def test_parse_retry_after_invalid():
    assert parse_retry_after(None) is None
    assert parse_retry_after("") is None
    assert parse_retry_after("not-a-number") is None

def test_classify_httpx_status_error():
    # 429
    exc = httpx.HTTPStatusError("429 Too Many Requests", request=httpx.Request("GET", "url"), response=MockResponse(429, {"retry-after": "10"}))
    classification = classify_error(exc, "groq")
    assert classification.category == AegisProviderErrorType.RATE_LIMITED
    assert classification.retryable is True
    assert classification.fallback_eligible is True
    assert classification.retry_after_seconds == 10
    
    # 401
    exc_401 = httpx.HTTPStatusError("Unauthorized", request=httpx.Request("GET", "url"), response=MockResponse(401))
    class_401 = classify_error(exc_401, "groq")
    assert class_401.category == AegisProviderErrorType.AUTHENTICATION_ERROR
    assert class_401.retryable is False
    assert class_401.fallback_eligible is True  # We want to fallback to the next provider on Auth err
    
    # 400 Bad Request
    exc_400 = httpx.HTTPStatusError("Bad Request", request=httpx.Request("GET", "url"), response=MockResponse(400))
    class_400 = classify_error(exc_400, "groq")
    assert class_400.category == AegisProviderErrorType.BAD_REQUEST
    assert class_400.retryable is False
    assert class_400.fallback_eligible is True
    
    # 5xx Server Error
    exc_500 = httpx.HTTPStatusError("Internal Server Error", request=httpx.Request("GET", "url"), response=MockResponse(500))
    class_500 = classify_error(exc_500, "groq")
    assert class_500.category == AegisProviderErrorType.SERVER_ERROR
    assert class_500.retryable is True
    assert class_500.fallback_eligible is True

def test_classify_httpx_timeout_and_network():
    exc_timeout = httpx.TimeoutException("Timeout")
    class_time = classify_error(exc_timeout, "groq")
    assert class_time.category == AegisProviderErrorType.TIMEOUT
    assert class_time.fallback_eligible is True
    
    exc_net = httpx.NetworkError("Network Error")
    class_net = classify_error(exc_net, "groq")
    assert class_net.category == AegisProviderErrorType.NETWORK_ERROR
    assert class_net.fallback_eligible is True

def test_classify_generic_exception():
    # Test string matching for native SDKs (e.g. Gemini)
    exc = Exception("quota exceeded 429")
    class_rate = classify_error(exc, "gemini")
    assert class_rate.category == AegisProviderErrorType.RATE_LIMITED
    assert class_rate.fallback_eligible is True
    
    exc_auth = Exception("unauthorized invalid api key")
    class_auth = classify_error(exc_auth, "gemini")
    assert class_auth.category == AegisProviderErrorType.AUTHENTICATION_ERROR
    assert class_auth.fallback_eligible is True

    exc_unknown = Exception("something completely different")
    class_unknown = classify_error(exc_unknown, "gemini")
    assert class_unknown.category == AegisProviderErrorType.UNKNOWN_PROVIDER_ERROR
    assert class_unknown.fallback_eligible is True

def test_security_payload_not_in_exception():
    exc_auth = Exception("unauthorized API key XYZ123 payload <script>alert(1)</script>")
    class_auth = classify_error(exc_auth, "gemini")
    
    # Check that classification only exposes ENUMs, safe statuses, and safe provider names, 
    # and NEVER stores the exception text
    assert class_auth.category == AegisProviderErrorType.AUTHENTICATION_ERROR
    assert not hasattr(class_auth, "raw_message")
