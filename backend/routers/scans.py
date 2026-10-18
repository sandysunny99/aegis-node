"""
Aegis Node — Scan history API.

GET /api/v1/scans                          paginated scans, newest first, with filters
GET /api/v1/scans/{scan_id}                one scan (report + dataset + target)
GET /api/v1/scans/{scan_id}/events         that scan's event timeline
GET /api/v1/datasets/{dataset_id}/scans    a dataset's scans over time (incl. verification re-scans)
GET /api/v1/datasets/{dataset_id}/events   a dataset's full timeline (upload, scans, AI, remediation)

Scan ids are unguessable public ids. Like /history (S1), listing every scan in a
public production deployment without an API key is refused; pass ?ids= with the
caller's own dataset ids instead. Every list response carries `persistence` so the
UI can say when history will not survive a restart.
"""

import re
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
from models import DatasetRecord, ScanEventRecord, ScanReportRecord  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402
from schemas import TIFusionReport  # noqa: E402
from services.detector_status import persistence_info  # noqa: E402
from sqlalchemy import desc, select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from utils.auth import require_api_key  # noqa: E402
from utils.datasets import get_dataset_by_public_id  # noqa: E402

router = APIRouter(prefix="/api/v1", tags=["history"])
_PUBLIC_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class Persistence(BaseModel):
    durable: bool
    database: str
    note: str


class ScanSummary(BaseModel):
    scan_id: str = Field(..., description="Public scan id")
    dataset_id: str
    target: str = Field(..., description="original | sanitized (verification re-scan)")
    file_format: str
    file_size_bytes: int
    sha256: str = Field(..., description="SHA-256 of the dataset as uploaded")
    started_at: datetime | None = Field(None, description="Null for scans recorded before history existed")
    completed_at: datetime
    verdict: str
    dataset_status: str = Field(..., description="Current stored status of the dataset")
    coverage_status: str
    rows_inspected: int
    rows_total: int | None
    clamav_status: str
    av_provider: str | None
    profile: str | None
    enrichment_status: str
    threats_found_count: int
    limitations: list[str]


class ScanList(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[ScanSummary]
    persistence: Persistence


class ScanEvent(BaseModel):
    event_type: str
    outcome: str = Field(..., description="ok | failed")
    created_at: datetime
    scan_id: str | None
    detail: dict


class EventList(BaseModel):
    items: list[ScanEvent]
    persistence: Persistence


class ScanDetail(ScanSummary):
    risk_score: float
    findings: list[dict]
    threat_intel: TIFusionReport | None


def _enrichment(report: ScanReportRecord) -> tuple[str, TIFusionReport | None]:
    try:
        ti = TIFusionReport(**report.threat_intel)
        return ti.enrichment_status, ti
    except (TypeError, ValueError):
        return "DISABLED", None


def _summary(report: ScanReportRecord, dataset: DatasetRecord) -> dict:
    enrichment, _ = _enrichment(report)
    return dict(
        scan_id=report.public_id,
        dataset_id=dataset.public_id,
        target=report.scan_target,
        file_format=dataset.file_format,
        file_size_bytes=dataset.file_size_bytes,
        sha256=dataset.sha256_hash,
        started_at=report.started_at,
        completed_at=report.scanned_at,
        verdict=report.verdict,
        dataset_status=dataset.status,
        coverage_status=report.coverage_status,
        rows_inspected=report.rows_inspected,
        rows_total=report.rows_total,
        clamav_status=report.clamav_status,
        av_provider=report.av_provider,
        profile=report.profile,
        enrichment_status=enrichment,
        threats_found_count=report.threats_found_count,
        limitations=report.verification_limitations,
    )


def _event(e: ScanEventRecord) -> ScanEvent:
    return ScanEvent(
        event_type=e.event_type,
        outcome=e.outcome,
        created_at=e.created_at,
        scan_id=e.scan_report.public_id if e.scan_report is not None else None,
        detail=e.detail,
    )


def _scan_by_public_id(db: Session, scan_id: str) -> ScanReportRecord:
    if not _PUBLIC_ID_RE.fullmatch(scan_id or ""):
        raise HTTPException(status_code=404, detail="Resource not found.")
    report = db.scalar(select(ScanReportRecord).where(ScanReportRecord.public_id == scan_id))
    if report is None:
        raise HTTPException(status_code=404, detail="Resource not found.")
    return report


@router.get("/scans", response_model=ScanList, summary="Paginated scan history, newest first")
@limiter.limit("60/minute")
def list_scans(
    request: Request,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    ids: str | None = Query(default=None, max_length=3400,
                            description="Comma-separated public dataset ids (the caller's own uploads)"),
    verdict: str | None = Query(default=None, max_length=32),
    dataset_status: str | None = Query(default=None, max_length=32),
    file_format: str | None = Query(default=None, max_length=16),
    enrichment_status: str | None = Query(default=None, max_length=16),
    target: str = Query(default="original", pattern="^(original|sanitized|all)$"),
    since: datetime | None = Query(default=None, description="ISO 8601; completed at or after"),  # noqa: B008
    until: datetime | None = Query(default=None, description="ISO 8601; completed before"),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008
) -> ScanList:
    if ids is None and not settings.api_key and settings.app_env.lower() == "production":
        raise HTTPException(
            status_code=403,
            detail="Listing all scans requires an API key. Pass ?ids= for your own uploads.",
        )
    query = db.query(ScanReportRecord, DatasetRecord).join(
        DatasetRecord, ScanReportRecord.dataset_id == DatasetRecord.id)
    if ids is not None:
        wanted = [i.strip() for i in ids.split(",") if i.strip()][:100]
        query = query.filter(DatasetRecord.public_id.in_(wanted))
    if target != "all":
        query = query.filter(ScanReportRecord.scan_target == target)
    if verdict:
        query = query.filter(ScanReportRecord.verdict == verdict)
    if dataset_status:
        query = query.filter(DatasetRecord.status == dataset_status)
    if file_format:
        query = query.filter(DatasetRecord.file_format == file_format.lower())
    if since:
        query = query.filter(ScanReportRecord.scanned_at >= since)
    if until:
        query = query.filter(ScanReportRecord.scanned_at < until)
    # newest first; id breaks ties so pagination is stable
    rows = query.order_by(desc(ScanReportRecord.scanned_at), desc(ScanReportRecord.id)).all()
    items = [_summary(r, d) for r, d in rows]
    if enrichment_status:  # stored inside the TI JSON, so filtered after loading
        items = [i for i in items if i["enrichment_status"] == enrichment_status.upper()]
    start = (page - 1) * page_size
    return ScanList(total=len(items), page=page, page_size=page_size,
                    items=items[start:start + page_size], persistence=persistence_info())


@router.get("/scans/{scan_id}", response_model=ScanDetail, summary="One scan with its evidence")
@limiter.limit("60/minute")
def get_scan(
    request: Request,
    scan_id: str,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008
) -> ScanDetail:
    report = _scan_by_public_id(db, scan_id)
    _, ti = _enrichment(report)
    return ScanDetail(**_summary(report, report.dataset), risk_score=report.risk_score,
                      findings=report.findings, threat_intel=ti)


@router.get("/scans/{scan_id}/events", response_model=EventList, summary="Event timeline of one scan")
@limiter.limit("60/minute")
def get_scan_events(
    request: Request,
    scan_id: str,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008
) -> EventList:
    report = _scan_by_public_id(db, scan_id)
    events = (db.query(ScanEventRecord).filter(ScanEventRecord.scan_report_id == report.id)
              .order_by(ScanEventRecord.created_at, ScanEventRecord.id).all())
    return EventList(items=[_event(e) for e in events], persistence=persistence_info())


@router.get("/datasets/{dataset_id}/scans", response_model=ScanList, summary="A dataset's scans over time")
@limiter.limit("60/minute")
def get_dataset_scans(
    request: Request,
    dataset_id: str,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008
) -> ScanList:
    dataset = get_dataset_by_public_id(db, dataset_id)
    reports = sorted(dataset.scan_reports, key=lambda r: (r.scanned_at, r.id), reverse=True)
    items = [_summary(r, dataset) for r in reports]
    return ScanList(total=len(items), page=1, page_size=len(items) or 1, items=items,
                    persistence=persistence_info())


@router.get("/datasets/{dataset_id}/events", response_model=EventList, summary="A dataset's full timeline")
@limiter.limit("60/minute")
def get_dataset_events(
    request: Request,
    dataset_id: str,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008
) -> EventList:
    dataset = get_dataset_by_public_id(db, dataset_id)
    events = (db.query(ScanEventRecord).filter(ScanEventRecord.dataset_id == dataset.id)
              .order_by(ScanEventRecord.created_at, ScanEventRecord.id).all())
    return EventList(items=[_event(e) for e in events], persistence=persistence_info())
