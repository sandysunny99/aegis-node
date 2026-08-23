"""
Tests for Cloudflare Turnstile Verification Utility.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from utils.turnstile import verify_turnstile_token


@pytest.mark.asyncio
async def test_turnstile_bypass_when_secret_unset():
    """When CLOUDFLARE_TURNSTILE_SECRET_KEY is empty, validation passes automatically."""
    with patch("utils.turnstile.settings") as mock_settings:
        mock_settings.cloudflare_turnstile_secret_key = ""
        assert await verify_turnstile_token(None) is True
        assert await verify_turnstile_token("") is True
        assert await verify_turnstile_token("any-token") is True


@pytest.mark.asyncio
async def test_turnstile_rejects_empty_token_when_enabled():
    """When secret is set, empty token must be rejected."""
    with patch("utils.turnstile.settings") as mock_settings:
        mock_settings.cloudflare_turnstile_secret_key = "0x4AAAAAAtest"
        assert await verify_turnstile_token(None) is False
        assert await verify_turnstile_token("") is False


@pytest.mark.asyncio
async def test_turnstile_successful_verification():
    """Mock successful response from Cloudflare siteverify endpoint."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": True}

    with (
        patch("utils.turnstile.settings") as mock_settings,
        patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp),
    ):
        mock_settings.cloudflare_turnstile_secret_key = "0x4AAAAAAtest"
        res = await verify_turnstile_token("valid-turnstile-token", remote_ip="127.0.0.1")
        assert res is True


@pytest.mark.asyncio
async def test_turnstile_failed_verification():
    """Mock failed response from Cloudflare siteverify endpoint."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"success": False, "error-codes": ["invalid-input-response"]}

    with (
        patch("utils.turnstile.settings") as mock_settings,
        patch("httpx.AsyncClient.post", new_callable=AsyncMock, return_value=mock_resp),
    ):
        mock_settings.cloudflare_turnstile_secret_key = "0x4AAAAAAtest"
        res = await verify_turnstile_token("bad-token")
        assert res is False
