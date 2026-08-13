"""
tests/test_llm.py — Unit & Integration tests for LLM Threat Analysis service & endpoints.

Security & Integrity Requirements Tested:
  - Missing API key returns status="unavailable" without crashing or HTTP 500.
  - Successful mocked Gemini call returns validated Pydantic structured output.
  - Malformed LLM provider response returns status="failed" without crashing.
  - POST /analyse and GET /analysis endpoints return structured JSON.
  - NEVER calls live Gemini API in pytest.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent / "scanner"))

from database import Base, create_all_tables, engine
from main import app
from services.llm_service import LlmAnalysisOutput, analyse

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


def test_analyse_missing_api_key(monkeypatch):
    """When GEMINI_API_KEY is not set, analyse() returns status='unavailable' gracefully."""
    monkeypatch.setattr("config.settings.gemini_api_key", "")

    result = analyse(
        dataset_id=1,
        file_format="csv",
        file_size_bytes=1024,
        clamav_status="clean",
        risk_score=0.0,
        findings=[],
    )

    assert result.status == "unavailable"
    assert result.verdict == "inconclusive"
    assert result.error == "GEMINI_API_KEY not configured"
    assert "unavailable" in result.summary.lower()


def test_analyse_successful_mocked_gemini(monkeypatch):
    """Mocked Gemini client returning valid JSON matching LlmAnalysisOutput."""
    monkeypatch.setattr("config.settings.gemini_api_key", "fake-test-key")

    mock_output = LlmAnalysisOutput(
        verdict="suspicious",
        severity="medium",
        confidence=0.85,
        summary="Automated scanner detected CSV formula injection patterns in column email.",
        evidence=["FORM-001 detected at row 5"],
        recommendations=["Sanitize leading equals signs before exporting to Excel"],
        limitations=["AI evaluation based strictly on scanner metadata"],
    )

    mock_response = MagicMock()
    mock_response.text = mock_output.model_dump_json()
    mock_response.usage_metadata.prompt_token_count = 120
    mock_response.usage_metadata.candidates_token_count = 45

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client):
        result = analyse(
            dataset_id=10,
            file_format="csv",
            file_size_bytes=2048,
            clamav_status="clean",
            risk_score=4.5,
            findings=[{
                "rule_id": "FORM-001",
                "severity": "high",
                "category": "formula_injection",
                "description": "Formula trigger",
                "location": "column=email, row=5",
            }],
        )

    assert result.status == "completed"
    assert result.verdict == "suspicious"
    assert result.severity == "medium"
    assert result.confidence == 0.85
    assert result.prompt_tokens == 120
    assert result.completion_tokens == 45
    assert len(result.evidence) == 1
    assert result.error is None


def test_analyse_malformed_json_fallback(monkeypatch):
    """When Gemini returns malformed non-JSON text, returns status='failed' without crashing."""
    monkeypatch.setattr("config.settings.gemini_api_key", "fake-test-key")

    mock_response = MagicMock()
    mock_response.text = "This is not valid JSON output!"

    mock_client = MagicMock()
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client):
        result = analyse(
            dataset_id=10,
            file_format="csv",
            file_size_bytes=2048,
            clamav_status="clean",
            risk_score=2.0,
            findings=[],
        )

    assert result.status == "failed"
    assert result.verdict == "inconclusive"
    assert result.error == "LLM analysis failed"


def test_analyse_endpoint_integration(monkeypatch):
    """Integration test for POST /api/v1/datasets/{id}/analyse endpoint."""
    monkeypatch.setattr("config.settings.gemini_api_key", "")

    # 1. Upload a dataset
    csv_bytes = b"name,score\nalice,100"
    upload_resp = client.post(
        "/api/v1/datasets/upload",
        files={"file": ("sample.csv", csv_bytes, "text/csv")},
    )
    dataset_id = upload_resp.json()["dataset_id"]

    # 2. Scan dataset
    client.post(f"/api/v1/datasets/{dataset_id}/scan")

    # 3. Call analyse endpoint
    analyse_resp = client.post(f"/api/v1/datasets/{dataset_id}/analyse")
    assert analyse_resp.status_code == 200
    body = analyse_resp.json()
    assert body["dataset_id"] == dataset_id
    assert body["status"] == "unavailable"

    # 4. GET latest analysis
    get_resp = client.get(f"/api/v1/datasets/{dataset_id}/analysis")
    assert get_resp.status_code == 200
    assert get_resp.json()["status"] == "unavailable"
