"""
Aegis Node — Scan History Router.
GET /api/v1/history — paginated list of all scanned datasets.
"""

import sys
from datetime import datetime
from pathlib import Path

_ROOT = Path(__file__).parent.parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from database import get_db  # noqa: E402
from fastapi import APIRouter, Depends, Query  # noqa: E402
from models import DatasetRecord  # noqa: E402
from pydantic import BaseModel  # noqa: E402
from sqlalchemy import desc  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

router = APIRouter(prefix="/api/v1", tags=["history"])


class HistoryItem(BaseModel):
    dataset_id: int
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
def get_history(
    page: int = Query(default=1, ge=1, description="Page number starting at 1"),
    page_size: int = Query(default=20, ge=1, le=100, description="Items per page (max 100)"),
    db: Session = Depends(get_db),  # noqa: B008
) -> HistoryResponse:
    query = db.query(DatasetRecord).order_by(desc(DatasetRecord.uploaded_at))
    total = query.count()
    records = query.offset((page - 1) * page_size).limit(page_size).all()

    items = []
    for rec in records:
        # Get latest scan report for dataset
        scans = rec.scan_reports
        scans_count = len(scans)
        latest = sorted(scans, key=lambda r: r.scanned_at)[-1] if scans else None

        verdict_map = {"quarantined": "malicious", "suspicious": "suspicious", "clean": "clean"}

        items.append(HistoryItem(
            dataset_id=rec.id,
            original_filename=rec.original_filename,
            file_size_bytes=rec.file_size_bytes,
            file_format=rec.file_format,
            status=rec.status,
            uploaded_at=rec.uploaded_at,
            scans_count=scans_count,
            risk_score=latest.risk_score if latest else None,
            threats_found_count=latest.threats_found_count if latest else None,
            verdict=verdict_map.get(rec.status) if latest else None,
            scanned_at=latest.scanned_at if latest else None,
        ))

    return HistoryResponse(total=total, page=page, page_size=page_size, items=items)
