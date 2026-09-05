"""
Tests for VirusTotal API v3 Hash-First Reputation Client.
"""

from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from services.threat_intelligence.virustotal import lookup_file_hash, ThreatIntelResult


@pytest.mark.asyncio
async def test_virustotal_unconfigured_when_disabled():
    """When ENABLE_VIRUSTOTAL is false, lookup returns unconfigured with zero network calls."""
    with patch("services.threat_intelligence.virustotal.settings") as mock_settings:
        mock_settings.enable_virustotal = False
        mock_settings.virustotal_api_key = "dummy-key"
        res = await lookup_file_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        assert res.status == "unconfigured"


@pytest.mark.asyncio
async def test_virustotal_empty_hash_handled():
    """Empty hash returns immediate error."""
    res = await lookup_file_hash("")
    assert res.status == "error"


@pytest.mark.asyncio
async def test_virustotal_successful_hash_reputation():
    """Mock successful response from VirusTotal API v3 for known malware hash."""
    test_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 58,
                    "suspicious": 1,
                    "harmless": 0,
                    "undetected": 13,
                },
                "popular_threat_classification": {
                    "suggested_threat_label": "Win.Trojan.EICAR",
                },
                "reputation": -85,
            }
        }
    }

    with (
        patch("services.threat_intelligence.virustotal.settings") as mock_settings,
        patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp) as mock_get,
    ):
        mock_settings.enable_virustotal = True
        mock_settings.virustotal_api_key = "valid-api-key"
        mock_settings.virustotal_timeout_seconds = 10

        res = await lookup_file_hash(test_hash)

        # Verify privacy: URL must query only the SHA-256 hash
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        assert test_hash in called_url
        assert "https://www.virustotal.com/api/v3/files/" in called_url

        # Check parsed stats
        assert res.status == "malicious"
        assert "Win.Trojan.EICAR" in res.tags


@pytest.mark.asyncio
async def test_virustotal_404_not_found():
    """When a hash is not in VirusTotal repository, returns not_found cleanly."""
    test_hash = "a" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 404

    with (
        patch("services.threat_intelligence.virustotal.settings") as mock_settings,
        patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp),
    ):
        mock_settings.enable_virustotal = True
        mock_settings.virustotal_api_key = "valid-api-key"
        mock_settings.virustotal_timeout_seconds = 10

        res = await lookup_file_hash(test_hash)
        assert res.status == "not_found"


@pytest.mark.asyncio
async def test_virustotal_429_rate_limited():
    """When API quota is exceeded, returns rate_limited without raising exception."""
    test_hash = "b" * 64
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with (
        patch("services.threat_intelligence.virustotal.settings") as mock_settings,
        patch("httpx.AsyncClient.get", new_callable=AsyncMock, return_value=mock_resp),
    ):
        mock_settings.enable_virustotal = True
        mock_settings.virustotal_api_key = "valid-api-key"
        mock_settings.virustotal_timeout_seconds = 10

        res = await lookup_file_hash(test_hash)
        assert res.status == "rate_limited"
