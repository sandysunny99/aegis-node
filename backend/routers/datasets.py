"""
Aegis Node — Dataset REST API Router.
Endpoints: upload, scan, status, report.
"""

import json
import sys
from pathlib import Path

# Ensure scanner/ package directory is resolvable from the router
_ROOT = Path(__file__).parent.parent.parent   # aegis-node/
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from database import get_db  # noqa: E402
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status  # noqa: E402
from fastapi.concurrency import run_in_threadpool  # noqa: E402
from models import DatasetRecord, ScanReportRecord  # noqa: E402
from schemas import (  # noqa: E402
    DatasetStatusResponse,
    DatasetUploadResponse,
    ScanResultResponse,
    ThreatFinding,
)
from services.file_service import file_service  # noqa: E402
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session  # noqa: E402
from utils.auth import require_api_key  # noqa: E402

from scanner.engine import run_scan  # noqa: E402

router = APIRouter(prefix="/api/v1/datasets", tags=["datasets"])

# Rate limiter instance (shares state with main app via singleton key function)
limiter = Limiter(key_func=get_remote_address)

# ─── Limits ───────────────────────────────────────────────────────────────────
_MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB (matches MAX_UPLOAD_SIZE_MB in config)


# ─── Upload ───────────────────────────────────────────────────────────────────

@router.post(
    "/upload",
    response_model=DatasetUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload a dataset file for scanning",
)
@limiter.limit("10/minute")    # Prevent storage/bandwidth abuse
async def upload_dataset(
    request: Request,             # Required by slowapi for rate limit tracking
    file: UploadFile = File(..., description="Dataset file — CSV, Parquet, JSON, JSONL, XLSX, TXT"),  # noqa: B008
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # API key guard (optional in dev)
) -> DatasetUploadResponse:
    # 1. Extension validation
    if not file_service.validate_extension(file.filename or ""):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"File type not allowed. Accepted: csv, parquet, json, jsonl. Got: {Path(file.filename or '').suffix!r}",
        )

    # 2. Read content with size cap
    content = await file.read()
    if len(content) > _MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {_MAX_UPLOAD_BYTES // (1024*1024)} MB.",
        )

    # 3. Save to data/samples/ under UUID filename
    meta = file_service.save_upload(file.filename or "upload", content)

    # 4. Persist to database
    record = DatasetRecord(
        original_filename=meta["original_filename"],
        stored_filename=meta["stored_filename"],
        file_size_bytes=meta["file_size_bytes"],
        sha256_hash=meta["sha256_hash"],
        mime_type=meta["mime_type"],
        file_format=meta["file_format"],
        status="uploaded",
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    return DatasetUploadResponse(
        dataset_id=record.id,
        original_filename=record.original_filename,
        stored_filename=record.stored_filename,
        file_size_bytes=record.file_size_bytes,
        sha256_hash=record.sha256_hash,
        mime_type=record.mime_type,
        file_format=record.file_format,
        status=record.status,
        uploaded_at=record.uploaded_at,
    )


# ─── Scan ─────────────────────────────────────────────────────────────────────

@router.post(
    "/{dataset_id}/scan",
    response_model=ScanResultResponse,
    summary="Execute multi-stage threat scan on an uploaded dataset",
)
@limiter.limit("20/minute")    # Prevent CPU/ClamAV abuse — scans are compute-intensive
async def scan_dataset(request: Request, dataset_id: int, db: Session = Depends(get_db)) -> ScanResultResponse:  # noqa: B008
    # Retrieve dataset record
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")

    if not file_service.sample_exists(record.stored_filename):
        raise HTTPException(status_code=404, detail="Dataset file not found on disk.")

    # Mark as scanning
    record.status = "scanning"
    db.commit()

    # Run blocking scan in threadpool — keeps the event loop free for health checks
    file_path = str(file_service.get_sample_path(record.stored_filename))
    result = await run_in_threadpool(run_scan, file_path)

    # Update status
    if result.verdict == "malicious":
        record.status = "quarantined"
        file_service.quarantine(record.stored_filename)
    elif result.verdict == "suspicious":
        record.status = "suspicious"
    else:
        record.status = "clean"
    db.commit()

    # Persist scan report
    report = ScanReportRecord(
        dataset_id=record.id,
        clamav_status=result.clamav_status,
        clamav_virus_name=result.clamav_virus_name,
        threats_found_count=result.threats_found_count,
        risk_score=result.risk_score,
        scan_duration_ms=result.scan_duration_ms,
        findings_json=json.dumps(result.to_findings_dicts()),
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    findings = [ThreatFinding(**f) for f in report.findings]

    return ScanResultResponse(
        scan_id=report.id,
        dataset_id=record.id,
        clamav_status=report.clamav_status,
        clamav_virus_name=report.clamav_virus_name,
        threats_found_count=report.threats_found_count,
        risk_score=report.risk_score,
        scan_duration_ms=report.scan_duration_ms,
        scanned_at=report.scanned_at,
        verdict=result.verdict,
        findings=findings,
    )


# ─── Status ───────────────────────────────────────────────────────────────────

@router.get(
    "/{dataset_id}",
    response_model=DatasetStatusResponse,
    summary="Get dataset upload status",
)
def get_dataset_status(dataset_id: int, db: Session = Depends(get_db)) -> DatasetStatusResponse:  # noqa: B008
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")
    return DatasetStatusResponse(
        dataset_id=record.id,
        original_filename=record.original_filename,
        file_size_bytes=record.file_size_bytes,
        sha256_hash=record.sha256_hash,
        status=record.status,
        uploaded_at=record.uploaded_at,
    )


# ─── Report ───────────────────────────────────────────────────────────────────

@router.get(
    "/{dataset_id}/report",
    response_model=ScanResultResponse,
    summary="Retrieve the latest scan report for a dataset",
)
def get_scan_report(dataset_id: int, db: Session = Depends(get_db)) -> ScanResultResponse:  # noqa: B008
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Dataset {dataset_id} not found.")

    if not record.scan_reports:
        raise HTTPException(status_code=404, detail="No scan report found. Run /scan first.")

    report: ScanReportRecord = sorted(record.scan_reports, key=lambda r: r.scanned_at)[-1]
    findings = [ThreatFinding(**f) for f in report.findings]

    # Derive verdict from stored status
    verdict_map = {"quarantined": "malicious", "suspicious": "suspicious", "clean": "clean"}
    verdict = verdict_map.get(record.status, "clean")

    return ScanResultResponse(
        scan_id=report.id,
        dataset_id=record.id,
        clamav_status=report.clamav_status,
        clamav_virus_name=report.clamav_virus_name,
        threats_found_count=report.threats_found_count,
        risk_score=report.risk_score,
        scan_duration_ms=report.scan_duration_ms,
        scanned_at=report.scanned_at,
        verdict=verdict,
        findings=findings,
    )
