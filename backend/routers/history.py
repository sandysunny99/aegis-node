"""
Aegis Node — Scan History Router.
GET /api/v1/history — paginated list of all scanned datasets.
"""

import sys
from datetime import datetime
from pathlib import Path

_curr = Path(__file__).resolve().parent
_ROOT = _curr.parent.parent if _curr.parent.name == "backend" else _curr.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import settings  # noqa: E402
from database import get_db  # noqa: E402
from fastapi import APIRouter, Depends, HTTPException, Query, Request  # noqa: E402
from limiter import limiter  # noqa: E402
from models import DatasetRecord  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from sqlalchemy import desc  # noqa: E402
from sqlalchemy.orm import Session, joinedload  # noqa: E402
from utils.auth import require_api_key  # noqa: E402

router = APIRouter(prefix="/api/v1", tags=["history"])


class HistoryItem(BaseModel):
    dataset_id: str
    original_filename: str
    file_size_bytes: int
    file_format: str
    status: str
    uploaded_at: datetime
    scans_count: int = 0
    risk_score: float | None = None
    threats_found_count: int | None = None
    verdict: str | None = None
    scanned_at: datetime | None = None


class HistoryResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[HistoryItem]


@router.get(
    "/history",
    response_model=HistoryResponse,
    summary="Paginated list of uploaded datasets and their latest scan outcomes",
)
@limiter.limit("60/minute")
def get_history(
    request: Request,
    page: int = Query(default=1, ge=1, description="Page number starting at 1"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page (max 100)"),
    ids: str | None = Query(
        default=None,
        max_length=3400,
        description="Comma-separated public dataset ids to list (the caller's own uploads)",
    ),
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # A-011: protect scan history
) -> HistoryResponse:
    # S1: without an API key nobody is an admin, so a public production deployment
    # only lists datasets whose unguessable ids the caller already holds.
    wanted = [i.strip() for i in (ids or "").split(",") if i.strip()][:100]
    if ids is None and not settings.api_key and settings.app_env.lower() == "production":
        raise HTTPException(
            status_code=403,
            detail="Listing all datasets requires an API key. Pass ?ids= for your own uploads.",
        )

    query = db.query(DatasetRecord)
    if ids is not None:
        query = query.filter(DatasetRecord.public_id.in_(wanted))

    # Separate count query to avoid joinedload subquery overhead (FINDING-019)
    total = query.count()

    records = (
        query
        .options(joinedload(DatasetRecord.scan_reports))
        .order_by(desc(DatasetRecord.uploaded_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    items = []
    for rec in records:
        # Get latest scan report for dataset
        scans = rec.scan_reports
        scans_count = len(scans)
        latest = sorted(scans, key=lambda r: r.scanned_at)[-1] if scans else None

        verdict_map = {"quarantined": "malicious", "suspicious": "suspicious", "clean": "clean"}
        verdict = getattr(latest, "verdict", None) if latest else None
        if not verdict:
            verdict = verdict_map.get(rec.status) if latest else None

        items.append(HistoryItem(
            dataset_id=rec.public_id,
            original_filename=rec.original_filename,
            file_size_bytes=rec.file_size_bytes,
            file_format=rec.file_format,
            status=rec.status,
            uploaded_at=rec.uploaded_at,
            scans_count=scans_count,
            risk_score=latest.risk_score if latest else None,
            threats_found_count=latest.threats_found_count if latest else None,
            verdict=verdict,
            scanned_at=latest.scanned_at if latest else None,
        ))

    return HistoryResponse(total=total, page=page, page_size=page_size, items=items)

