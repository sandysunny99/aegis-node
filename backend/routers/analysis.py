"""
Aegis Node — LLM Analysis Router.
POST /api/v1/datasets/{dataset_id}/analyse
GET  /api/v1/datasets/{dataset_id}/analysis
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import json  # noqa: E402

from database import get_db  # noqa: E402
from fastapi import APIRouter, Depends, HTTPException  # noqa: E402
from models import DatasetRecord, LlmAnalysisRecord  # noqa: E402
from schemas import AnalysisResponse  # noqa: E402
from services.llm_service import analyse  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

router = APIRouter(prefix="/api/v1/datasets", tags=["analysis"])


@router.post(
    "/{dataset_id}/analyse",
    response_model=AnalysisResponse,
    summary="Run Gemini AI threat analysis on a scanned dataset",
)
def analyse_dataset(dataset_id: int, db: Session = Depends(get_db)) -> AnalysisResponse:  # noqa: B008
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")

    if not record.scan_reports:
        raise HTTPException(
            status_code=400,
            detail="Run /scan before requesting AI analysis.",
        )

    # Use latest scan report findings
    latest_report = sorted(record.scan_reports, key=lambda r: r.scanned_at)[-1]
    findings = latest_report.findings

    # Call LLM service with compact evidence payload
    result = analyse(
        dataset_id=record.id,
        file_format=record.file_format,
        file_size_bytes=record.file_size_bytes,
        clamav_status=latest_report.clamav_status,
        risk_score=latest_report.risk_score,
        findings=findings,
    )

    # Persist result record
    db_record = LlmAnalysisRecord(
        dataset_id=record.id,
        scan_report_id=latest_report.id,
        model_name=result.model_name,
        status=result.status,
        verdict=result.verdict,
        severity=result.severity,
        confidence=result.confidence,
        summary=result.summary,
        evidence_json=json.dumps(result.evidence),
        recommendations_json=json.dumps(result.recommendations),
        limitations_json=json.dumps(result.limitations),
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        error_message=result.error,
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return AnalysisResponse(
        analysis_id=db_record.id,
        dataset_id=db_record.dataset_id,
        model_name=db_record.model_name,
        status=db_record.status,
        verdict=db_record.verdict,
        severity=db_record.severity,
        confidence=db_record.confidence,
        summary=db_record.summary,
        evidence=db_record.evidence,
        recommendations=db_record.recommendations,
        limitations=db_record.limitations,
        prompt_tokens=db_record.prompt_tokens,
        completion_tokens=db_record.completion_tokens,
        created_at=db_record.created_at,
        error=result.error,
    )


@router.get(
    "/{dataset_id}/analysis",
    response_model=AnalysisResponse,
    summary="Get the latest AI analysis for a dataset",
)
def get_analysis(dataset_id: int, db: Session = Depends(get_db)) -> AnalysisResponse:  # noqa: B008
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")

    if not record.llm_analyses:
        raise HTTPException(status_code=404, detail="No AI analysis found. Run /analyse first.")

    latest = sorted(record.llm_analyses, key=lambda a: a.created_at)[-1]

    return AnalysisResponse(
        analysis_id=latest.id,
        dataset_id=latest.dataset_id,
        model_name=latest.model_name,
        status=latest.status,
        verdict=latest.verdict,
        severity=latest.severity,
        confidence=latest.confidence,
        summary=latest.summary,
        evidence=latest.evidence,
        recommendations=latest.recommendations,
        limitations=latest.limitations,
        prompt_tokens=latest.prompt_tokens,
        completion_tokens=latest.completion_tokens,
        created_at=latest.created_at,
        error=latest.error_message,
    )
