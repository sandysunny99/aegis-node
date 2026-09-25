import email.utils
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

class AegisProviderErrorType(Enum):
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    AUTHENTICATION_ERROR = "authentication_error"
    AUTHORIZATION_ERROR = "authorization_error"
    BAD_REQUEST = "bad_request"
    SERVER_ERROR = "server_error"
    NETWORK_ERROR = "network_error"
    CONTEXT_LIMIT = "context_limit"
    UNKNOWN_PROVIDER_ERROR = "unknown_provider_error"

@dataclass
class ProviderErrorClassification:
    category: AegisProviderErrorType
    retryable: bool
    fallback_eligible: bool
    retry_after_seconds: Optional[int] = None
    provider: Optional[str] = None
    http_status: Optional[int] = None

def parse_retry_after(header_value: Optional[str], max_delay: int = 60) -> Optional[int]:
    """
    Parse Retry-After header. Supports delta-seconds and HTTP-date.
    Clamps to max_delay to prevent unbounded sleep or provider control.
    """
    if not header_value:
        return None
    header_value = header_value.strip()
    if not header_value:
        return None

    # Try delta-seconds
    try:
        delay = int(header_value)
        return min(max(0, delay), max_delay)
    except ValueError:
        pass

    # Try HTTP-date
    try:
        import calendar
        parsed_tuple = email.utils.parsedate(header_value)
        if parsed_tuple:
            timestamp = calendar.timegm(parsed_tuple)
            delay = int(timestamp - time.time())
            return min(max(0, delay), max_delay)
    except Exception:
        pass

    return None

def classify_error(exc: Exception, provider: str = "unknown", max_retry_after: int = 60) -> ProviderErrorClassification:
    """
    Classify provider exceptions natively without external dependencies.
    Fallback eligible means we can move to the next provider in the chain.
    """
    import httpx
    
    status = None
    retry_after = None

    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        retry_after = parse_retry_after(exc.response.headers.get("retry-after"), max_delay=max_retry_after)

        if status == 429:
            return ProviderErrorClassification(AegisProviderErrorType.RATE_LIMITED, True, True, retry_after, provider, status)
        elif status == 401:
            return ProviderErrorClassification(AegisProviderErrorType.AUTHENTICATION_ERROR, False, True, None, provider, status)
        elif status == 403:
            return ProviderErrorClassification(AegisProviderErrorType.AUTHORIZATION_ERROR, False, True, None, provider, status)
        elif status in (400, 422):
            return ProviderErrorClassification(AegisProviderErrorType.BAD_REQUEST, False, True, None, provider, status)
        elif status == 413:
            return ProviderErrorClassification(AegisProviderErrorType.CONTEXT_LIMIT, False, True, None, provider, status)
        elif status == 408:
            return ProviderErrorClassification(AegisProviderErrorType.TIMEOUT, True, True, retry_after, provider, status)
        elif status >= 500:
            return ProviderErrorClassification(AegisProviderErrorType.SERVER_ERROR, True, True, retry_after, provider, status)
        else:
            return ProviderErrorClassification(AegisProviderErrorType.UNKNOWN_PROVIDER_ERROR, False, True, None, provider, status)

    if isinstance(exc, httpx.TimeoutException):
        return ProviderErrorClassification(AegisProviderErrorType.TIMEOUT, True, True, None, provider, None)
    if isinstance(exc, httpx.NetworkError):
        return ProviderErrorClassification(AegisProviderErrorType.NETWORK_ERROR, True, True, None, provider, None)

    # Generic string-based classification for providers using native SDKs (e.g., Gemini)
    exc_str = str(exc).lower()
    if "429" in exc_str or "quota" in exc_str or "rate limit" in exc_str or "resource_exhausted" in exc_str:
        return ProviderErrorClassification(AegisProviderErrorType.RATE_LIMITED, True, True, None, provider, None)
    if "401" in exc_str or "403" in exc_str or "unauthorized" in exc_str or "authentication" in exc_str or "api key" in exc_str:
        return ProviderErrorClassification(AegisProviderErrorType.AUTHENTICATION_ERROR, False, True, None, provider, None)
    if "timeout" in exc_str:
        return ProviderErrorClassification(AegisProviderErrorType.TIMEOUT, True, True, None, provider, None)
    if "connect" in exc_str or "refused" in exc_str:
        return ProviderErrorClassification(AegisProviderErrorType.NETWORK_ERROR, True, True, None, provider, None)

    return ProviderErrorClassification(AegisProviderErrorType.UNKNOWN_PROVIDER_ERROR, False, True, None, provider, None)
