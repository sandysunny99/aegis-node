"""
tests/test_ai_fallback.py
Unit tests for the AI provider fallback chain.
All tests use unittest.mock — no real API calls are made.

Tests cover:
  1. Primary rate-limit → fallback provider succeeds
  2. Primary invalid JSON → fallback parses correctly
  3. All providers fail → _unavailable_result() returned
  4. No fallback configured → behaves exactly as before (primary only)
  5. Primary success → fallback never called (short-circuit)
  6. Unknown provider name in chain → skipped gracefully
  7. Fallback key preferred over primary key when configured
  8. 'none' in chain → skipped, does not count as failure
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Path setup so imports work from project root ───────────────────────────────
_BACKEND = Path(__file__).parent.parent / "backend"
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from services.llm_service import (
    LlmAnalysisResult,
    _build_provider_chain,
    _get_provider_key,
    analyse,
)

# ── Shared fixtures ────────────────────────────────────────────────────────────

EVIDENCE_KWARGS = dict(
    dataset_id=1,
    file_format="csv",
    file_size_bytes=1024,
    clamav_status="CLEAN",
    risk_score=75.0,
    findings=[{"rule_id": "SQLI-001", "severity": "high",
                "category": "sql_injection", "description": "test", "location": "col=A,row=1"}],
)

def _success_result(model: str = "test-model") -> LlmAnalysisResult:
    """Helper: fabricate a completed LlmAnalysisResult."""
    return LlmAnalysisResult(
        status="completed",
        model_name=model,
        verdict="high_risk",
        severity="high",
        confidence=0.92,
        summary="SQL injection detected in dataset.",
        evidence=["SQLI-001 at col=A"],
        recommendations=["Review and sanitize the dataset."],
        limitations=["AI assessment is advisory only."],
    )


def _failed_result(model: str = "test-model", reason: str = "Rate limit") -> LlmAnalysisResult:
    return LlmAnalysisResult(status="failed", model_name=model, error=reason)


def _unavailable_result(model: str = "test-model", reason: str = "unavailable") -> LlmAnalysisResult:
    return LlmAnalysisResult(status="unavailable", model_name=model, error=reason)


# ── Tests: _build_provider_chain ───────────────────────────────────────────────

class TestBuildProviderChain:
    """Verify the chain builder returns correct (name, is_fallback) tuples."""

    def test_primary_only_no_fallback(self):
        """When AI_FALLBACK_CHAIN is empty, chain has only the primary."""
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = ""
            chain = _build_provider_chain()
        assert chain == [("gemini", False)]

    def test_primary_plus_two_fallbacks(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "groq,ollama"
            chain = _build_provider_chain()
        assert chain == [("gemini", False), ("groq", True), ("ollama", True)]

    def test_unknown_provider_in_chain_skipped(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "banana,groq"  # 'banana' is unknown
            chain = _build_provider_chain()
        assert chain == [("gemini", False), ("groq", True)]

    def test_none_in_fallback_chain_skipped(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "none,groq"  # 'none' excluded from fallbacks
            chain = _build_provider_chain()
        assert chain == [("gemini", False), ("groq", True)]

    def test_whitespace_stripped_in_chain(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = " groq , ollama "
            chain = _build_provider_chain()
        assert chain == [("gemini", False), ("groq", True), ("ollama", True)]

    def test_primary_none_returns_only_none(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.ai_provider = "none"
            mock_cfg.ai_fallback_chain = ""
            chain = _build_provider_chain()
        assert chain == [("none", False)]


# ── Tests: _get_provider_key ───────────────────────────────────────────────────

class TestGetProviderKey:
    """Verify fallback key preference logic."""

    def test_gemini_primary_key_when_not_fallback(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.gemini_api_key = "primary-gemini-key"
            mock_cfg.fallback_gemini_api_key = "fallback-gemini-key"
            key = _get_provider_key("gemini", is_fallback=False)
        assert key == "primary-gemini-key"

    def test_gemini_fallback_key_when_is_fallback_and_key_set(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.gemini_api_key = "primary-gemini-key"
            mock_cfg.fallback_gemini_api_key = "fallback-gemini-key"
            key = _get_provider_key("gemini", is_fallback=True)
        assert key == "fallback-gemini-key"

    def test_gemini_falls_back_to_primary_when_no_fallback_key(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.gemini_api_key = "primary-gemini-key"
            mock_cfg.fallback_gemini_api_key = ""  # not set
            key = _get_provider_key("gemini", is_fallback=True)
        assert key == "primary-gemini-key"

    def test_groq_fallback_key_preferred(self):
        with patch("services.llm_service.settings") as mock_cfg:
            mock_cfg.groq_api_key = "primary-groq"
            mock_cfg.fallback_groq_api_key = "fallback-groq"
            key = _get_provider_key("groq", is_fallback=True)
        assert key == "fallback-groq"

    def test_ollama_returns_empty_string(self):
        key = _get_provider_key("ollama", is_fallback=False)
        assert key == ""


# ── Tests: analyse() — fallback chain behaviour ────────────────────────────────

class TestAnalyseFallbackChain:
    """Integration-style tests of analyse() with mocked provider calls."""

    # ── Test 1: Primary rate-limit → fallback succeeds ─────────────────────────
    def test_primary_rate_limit_fallback_succeeds(self):
        """Primary returns unavailable (rate limit) → fallback returns success."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "groq"
            mock_cfg.gemini_api_key = "key"
            mock_cfg.fallback_gemini_api_key = ""
            mock_cfg.fallback_groq_api_key = ""
            mock_cfg.groq_api_key = "groq-key"

            # Gemini rate-limited, Groq succeeds
            mock_call.side_effect = [
                _unavailable_result("gemini-2.0-flash", "rate limit"),
                _success_result("groq/llama-3.1-8b"),
            ]

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "completed"
        assert result.model_name == "groq/llama-3.1-8b"
        assert mock_call.call_count == 2   # Both providers tried

    # ── Test 2: Primary invalid JSON → fallback parses correctly ───────────────
    def test_primary_failed_parse_fallback_succeeds(self):
        """Primary returns _failed_result (bad JSON) → fallback returns success."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "ollama"
            mock_cfg.gemini_api_key = "key"
            mock_cfg.fallback_gemini_api_key = ""
            mock_cfg.fallback_groq_api_key = ""

            mock_call.side_effect = [
                _failed_result("gemini-2.0-flash", "Failed to parse Gemini structured response"),
                _success_result("ollama/llama3.1"),
            ]

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "completed"
        assert result.model_name == "ollama/llama3.1"
        assert mock_call.call_count == 2

    # ── Test 3: All providers fail → _unavailable_result() ─────────────────────
    def test_all_providers_fail_returns_unavailable(self):
        """All three providers fail → returns unavailable with chain_exhausted model."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "groq,ollama"
            mock_cfg.gemini_api_key = "key"
            mock_cfg.fallback_gemini_api_key = ""
            mock_cfg.fallback_groq_api_key = ""

            mock_call.side_effect = [
                _unavailable_result("gemini", "rate limit"),
                _failed_result("groq", "bad JSON"),
                _unavailable_result("ollama", "not reachable"),
            ]

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "unavailable"
        assert result.model_name == "chain_exhausted"
        assert mock_call.call_count == 3

    # ── Test 4: No fallback configured → behaves as before (primary only) ──────
    def test_no_fallback_primary_only(self):
        """Empty AI_FALLBACK_CHAIN — only one provider call is made."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = ""   # ← no fallback
            mock_cfg.gemini_api_key = "key"
            mock_cfg.fallback_gemini_api_key = ""
            mock_cfg.fallback_groq_api_key = ""

            mock_call.return_value = _success_result("gemini-2.0-flash")

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "completed"
        assert mock_call.call_count == 1   # Only one call — no fallback tried

    # ── Test 5: Primary succeeds → fallback never called ───────────────────────
    def test_primary_success_fallback_not_called(self):
        """When primary succeeds, fallback providers must NOT be called."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "groq,ollama"
            mock_cfg.gemini_api_key = "key"
            mock_cfg.fallback_gemini_api_key = ""
            mock_cfg.fallback_groq_api_key = ""

            mock_call.return_value = _success_result("gemini-2.0-flash")

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "completed"
        assert result.model_name == "gemini-2.0-flash"
        assert mock_call.call_count == 1   # Short-circuit — no fallback

    # ── Test 6: Unknown provider in chain → skipped gracefully ─────────────────
    def test_unknown_provider_in_chain_skipped(self):
        """Unknown provider name 'banana' is skipped; valid fallback 'groq' succeeds."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "groq"   # 'banana' already filtered in _build_provider_chain
            mock_cfg.gemini_api_key = "key"
            mock_cfg.fallback_gemini_api_key = ""
            mock_cfg.fallback_groq_api_key = ""

            mock_call.side_effect = [
                _failed_result("gemini", "bad JSON"),
                _success_result("groq/llama"),
            ]

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "completed"
        assert mock_call.call_count == 2

    # ── Test 7: provider=none → returns unavailable immediately ────────────────
    def test_provider_none_returns_unavailable_immediately(self):
        """ai_provider='none' → returns unavailable without calling any provider."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "none"
            mock_cfg.ai_fallback_chain = ""

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "unavailable"
        mock_call.assert_not_called()

    # ── Test 8: _call_provider raises exception → continue chain ───────────────
    def test_unexpected_exception_continues_chain(self):
        """If _call_provider raises unexpectedly, chain continues to next provider."""
        with (
            patch("services.llm_service.settings") as mock_cfg,
            patch("services.llm_service._call_provider") as mock_call,
        ):
            mock_cfg.ai_provider = "gemini"
            mock_cfg.ai_fallback_chain = "groq"
            mock_cfg.gemini_api_key = "key"
            mock_cfg.fallback_gemini_api_key = ""
            mock_cfg.fallback_groq_api_key = ""

            mock_call.side_effect = [
                RuntimeError("Unexpected network failure"),  # Primary raises
                _success_result("groq/llama"),              # Fallback succeeds
            ]

            result = analyse(**EVIDENCE_KWARGS)

        assert result.status == "completed"
        assert mock_call.call_count == 2
