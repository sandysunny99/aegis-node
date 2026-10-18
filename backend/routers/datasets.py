"""
Aegis Node — Dataset REST API Router.
Endpoints: upload, scan, status, report.
"""

import json
import logging
import sys
from datetime import UTC, datetime
from pathlib import Path

# Ensure scanner/ package directory is resolvable from the router
_curr = Path(__file__).resolve().parent
_ROOT = _curr.parent.parent if _curr.parent.name == "backend" else _curr.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from config import settings  # noqa: E402
from database import get_db  # noqa: E402
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status  # noqa: E402
from fastapi.concurrency import run_in_threadpool  # noqa: E402
from limiter import get_client_ip, limiter  # noqa: E402
from models import DatasetRecord, ScanReportRecord  # noqa: E402
from schemas import (  # noqa: E402
    DatasetStatusResponse,
    DatasetUploadResponse,
    ScanResultResponse,
    ThreatFinding,
    TIFusionReport,
)
from services.file_service import file_service  # noqa: E402
from services.history import detector_events, record_event, threat_intel_events  # noqa: E402
from services.threat_intelligence.enrichment import enrich_scan_result  # noqa: E402
from sqlalchemy import update  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from utils.auth import require_api_key  # noqa: E402
from utils.datasets import get_dataset_by_public_id  # noqa: E402
from utils.turnstile import verify_turnstile_token  # noqa: E402

from scanner.engine import run_scan  # noqa: E402

logger = logging.getLogger("aegis.datasets")

router = APIRouter(prefix="/api/v1/datasets", tags=["datasets"])

# ─── Limits ───────────────────────────────────────────────────────────────────
_MAX_UPLOAD_BYTES = settings.max_upload_size_mb * 1024 * 1024  # Enforces configured upload limit
_CHUNK_SIZE_BYTES = 1024 * 1024       # 1 MB chunk size for streaming upload


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
    # 0. Cloudflare Turnstile Bot Challenge Verification
    turnstile_token = request.headers.get("x-turnstile-token") or request.headers.get("cf-turnstile-token")
    client_ip = get_client_ip(request)  # S6: proxy headers only from trusted proxies
    if not await verify_turnstile_token(turnstile_token, remote_ip=client_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Bot verification unavailable.",
        )

    filename = file.filename or "upload"

    # 1. Extension validation
    if not file_service.validate_extension(filename):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=f"File type not allowed. Accepted extensions: {sorted(list(settings.allowed_extensions))}. Got: {Path(filename).suffix!r}",
        )

    # 2. Stream directly to disk with incremental SHA-256 and size enforcement
    max_bytes = settings.max_upload_size_mb * 1024 * 1024
    try:
        meta = await file_service.save_upload_stream(file, filename, max_bytes=max_bytes)
    except ValueError as exc:
        msg = str(exc)
        if "exceeds maximum allowed size" in msg:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=msg,
            ) from exc
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg,
        ) from exc

    # 3. Persist to database
    record = DatasetRecord(
        original_filename=meta["original_filename"],
        stored_filename=meta["stored_filename"],
        file_size_bytes=meta["file_size_bytes"],
        sha256_hash=meta["sha256_hash"],
        mime_type=meta["mime_type"],
        file_format=meta["file_format"],
        object_key=meta["object_key"],
        storage_backend=meta["storage_backend"],
        status="uploaded",
    )
    db.add(record)
    db.flush()
    record_event(db, "UPLOAD_ACCEPTED", dataset=record, file_format=record.file_format,
                 file_size_bytes=record.file_size_bytes, sha256=record.sha256_hash)
    db.commit()
    db.refresh(record)

    return DatasetUploadResponse(
        dataset_id=record.public_id,
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

_REMEDIATED_STATUSES = ("remediated", "partial_remediated", "remediated_unverified")

# Only a scan that proved the file clean is stored as "clean". A scan with
# limitations or one that could not finish keeps its own status, so it is never
# shown as clean (Phase A gap #1). Rows written before this change may still say
# "clean" for those verdicts; their stored report verdict is authoritative.
_DATASET_STATUS_BY_VERDICT = {
    "malicious": "quarantined",
    "suspicious": "suspicious",
    "clean_verified": "clean",
    "clean_with_limitations": "clean_limited",
    "scan_incomplete": "incomplete",
}


def dataset_status_for_verdict(verdict: str) -> str:
    """Map a scan verdict to the stored dataset status; unknown verdicts are incomplete."""
    return _DATASET_STATUS_BY_VERDICT.get(verdict, "incomplete")
_DISABLED_TI_JSON = (
    '{"status":"disabled","evidence":[],"evidence_strength":"NONE",'
    '"providers_checked":[],"limitations":[],"conflicts":[]}'
)


def _scan_response(record: DatasetRecord, report: ScanReportRecord) -> ScanResultResponse:
    """Build the API response for a persisted scan report."""
    ti_out = None
    try:
        if report.threat_intel:
            ti_out = TIFusionReport(**report.threat_intel)
    except (TypeError, ValueError):
        ti_out = None

    return ScanResultResponse(
        scan_id=report.id,
        scan_public_id=report.public_id,
        dataset_id=record.public_id,
        clamav_status=report.clamav_status,
        clamav_virus_name=report.clamav_virus_name,
        threats_found_count=report.threats_found_count,
        risk_score=report.risk_score,
        scan_duration_ms=report.scan_duration_ms,
        scanned_at=report.scanned_at,
        verdict=report.verdict,
        rows_inspected=report.rows_inspected,
        rows_total=report.rows_total,
        coverage_percentage=report.coverage_percentage,
        coverage_status=report.coverage_status,
        verification_limitations=report.verification_limitations,
        findings=[ThreatFinding(**f) for f in report.findings],
        threat_intel=ti_out,
        enrichment_status=ti_out.enrichment_status if ti_out else "DISABLED",
    )


@router.post(
    "/{dataset_id}/scan",
    response_model=ScanResultResponse,
    summary="Execute multi-stage threat scan on an uploaded dataset",
)
@limiter.limit("20/minute")    # Prevent CPU/ClamAV abuse — scans are compute-intensive
async def scan_dataset(
    request: Request,
    dataset_id: str,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # API key guard
) -> ScanResultResponse:
    record = get_dataset_by_public_id(db, dataset_id)

    if not file_service.sample_exists(record.stored_filename, record.object_key):
        raise HTTPException(status_code=404, detail="Dataset file not found on disk or storage backend.")

    # C1 / FINDING-025: refuse to re-scan a remediated original *before* touching status,
    # so the dataset keeps its remediated state.
    if record.remediations or record.status in _REMEDIATED_STATUSES:
        raise HTTPException(
            status_code=409,
            detail="Dataset has already been remediated. Re-scanning original is not permitted.",
        )

    # Guard against concurrent double-scan: atomic UPDATE WHERE status != 'scanning' (A-003)
    previous_status = record.status
    updated = db.execute(
        update(DatasetRecord)
        .where(DatasetRecord.id == record.id, DatasetRecord.status != "scanning")
        .values(status="scanning")
    )
    db.commit()
    if updated.rowcount == 0:
        raise HTTPException(status_code=409, detail="Scan already in progress for this dataset. Please wait.")
    db.refresh(record)
    started_at = datetime.now(UTC)
    av_provider = (settings.av_provider or "").strip().lower()
    started = record_event(db, "SCAN_STARTED", dataset=record, profile=settings.aegis_profile,
                           av_provider=av_provider)
    db.commit()

    # C2: everything after the status flip is guarded, so a failure anywhere
    # (scan, TI, quarantine move, DB write) can never leave the row in 'scanning'.
    try:
        # C3: quarantined files live in quarantine/, not samples/
        file_path = str(file_service.get_existing_source_path(record.stored_filename, record.object_key))
        result = await run_in_threadpool(run_scan, file_path)
        ti_report = await enrich_scan_result(result, file_path)

        if result.verdict == "malicious":
            file_service.quarantine(record.stored_filename)
        record.status = dataset_status_for_verdict(result.verdict)

        # FINDING-018: Persist scan report including verdict, coverage, and limitations
        report = ScanReportRecord(
            dataset_id=record.id,
            clamav_status=result.clamav_status,
            clamav_virus_name=result.clamav_virus_name,
            threats_found_count=result.threats_found_count,
            risk_score=result.risk_score,
            verdict=result.verdict,
            rows_inspected=result.rows_inspected,
            rows_total=result.rows_total,
            coverage_percentage=result.coverage_percentage,
            coverage_status=result.coverage_status,
            scan_duration_ms=result.scan_duration_ms,
            findings_json=json.dumps(result.to_findings_dicts()),
            verification_limitations_json=json.dumps(result.verification_limitations),
            threat_intel_json=ti_report.model_dump_json() if ti_report else _DISABLED_TI_JSON,
            started_at=started_at,
            profile=settings.aegis_profile,
            av_provider=av_provider,
        )
        db.add(report)
        db.flush()
        started.scan_report_id = report.id  # link the start event once the report exists
        detector_events(db, record, report, result)
        threat_intel_events(db, record, report, ti_report)
        record_event(db, "SCAN_COMPLETED", dataset=record, scan=report, verdict=result.verdict,
                     dataset_status=record.status, coverage_status=result.coverage_status,
                     enrichment_status=ti_report.enrichment_status if ti_report else "DISABLED",
                     limitations=result.verification_limitations, duration_ms=result.scan_duration_ms)
        db.commit()
        db.refresh(report)
    except Exception as exc:
        db.rollback()
        record = db.get(DatasetRecord, record.id)
        # Keep the last good state if there was one; otherwise mark the failure.
        record.status = previous_status if record.latest_scan_report else "error"
        record_event(db, "SCAN_FAILED", dataset=record, outcome="failed",
                     error=type(exc).__name__, dataset_status=record.status)
        db.commit()
        logger.exception("Scan failed for dataset %s", record.public_id)
        raise HTTPException(status_code=500, detail="Scan execution failed") from exc

    return _scan_response(record, report)


# ─── Status ───────────────────────────────────────────────────────────────────

@router.get(
    "/{dataset_id}",
    response_model=DatasetStatusResponse,
    summary="Get dataset upload status",
)
@limiter.limit("60/minute")
def get_dataset_status(
    request: Request,
    dataset_id: str,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # A-014
) -> DatasetStatusResponse:
    record = get_dataset_by_public_id(db, dataset_id)
    return DatasetStatusResponse(
        dataset_id=record.public_id,
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
@limiter.limit("60/minute")
def get_scan_report(
    request: Request,
    dataset_id: str,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # A-014
) -> ScanResultResponse:
    record = get_dataset_by_public_id(db, dataset_id)

    if record.latest_scan_report is None:
        raise HTTPException(status_code=404, detail="No scan report found. Run /scan first.")

    report: ScanReportRecord = record.latest_scan_report
    return _scan_response(record, report)
