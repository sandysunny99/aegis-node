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
import functools  # noqa: E402

from database import get_db  # noqa: E402
from fastapi import APIRouter, Depends, HTTPException, Request  # noqa: E402
from fastapi.concurrency import run_in_threadpool  # noqa: E402
from limiter import limiter  # noqa: E402
from models import DatasetRecord, LlmAnalysisRecord  # noqa: E402
from schemas import AnalysisResponse  # noqa: E402
from services.llm_service import analyse  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from utils.auth import require_api_key  # noqa: E402

router = APIRouter(prefix="/api/v1/datasets", tags=["analysis"])


@router.post(
    "/{dataset_id}/analyse",
    response_model=AnalysisResponse,
    summary="Run AI threat analysis on a scanned dataset (triggers external API call)",
)
@limiter.limit("5/minute")   # F7: AI calls are expensive — cap at 5/min per IP
async def analyse_dataset(
    request: Request,         # Required by slowapi for IP tracking
    dataset_id: int,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # Guard — triggers paid AI calls
) -> AnalysisResponse:
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if not record.scan_reports:
        raise HTTPException(
            status_code=400,
            detail="Run /scan before requesting AI analysis.",
        )

    # Use latest scan report findings
    latest_report = sorted(record.scan_reports, key=lambda r: r.scanned_at)[-1]
    findings = latest_report.findings

    # F1: Run blocking LLM network call in threadpool — keeps event loop free
    result = await run_in_threadpool(
        functools.partial(
            analyse,
            dataset_id=record.id,
            file_format=record.file_format,
            file_size_bytes=record.file_size_bytes,
            clamav_status=latest_report.clamav_status,
            risk_score=latest_report.risk_score,
            findings=findings,
        )
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
@limiter.limit("60/minute")
def get_analysis(
    request: Request,
    dataset_id: int,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008
) -> AnalysisResponse:
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")

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
