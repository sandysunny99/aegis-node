"""
Aegis Node — Dataset Remediation & Re-Scan Verification Router.
Endpoints:
  POST /api/v1/datasets/{dataset_id}/remediate
  GET  /api/v1/datasets/{dataset_id}/remediation
  GET  /api/v1/datasets/{dataset_id}/download-sanitized
"""

import json
import re
import secrets
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

_curr = Path(__file__).resolve().parent
_ROOT = _curr.parent.parent if _curr.parent.name == "backend" else _curr.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import logging
from config import settings  # noqa: E402
from database import get_db  # noqa: E402
from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status  # noqa: E402
from fastapi.concurrency import run_in_threadpool  # noqa: E402
from fastapi.responses import FileResponse  # noqa: E402
from limiter import limiter  # noqa: E402
from models import DatasetRecord, RemediationRecord  # noqa: E402
from schemas import RemediationActionSchema, RemediationResponse  # noqa: E402
from services.file_service import file_service  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from utils.auth import require_api_key  # noqa: E402

from scanner.engine import run_scan  # noqa: E402
from scanner.sanitizer import sanitize_file  # noqa: E402

logger = logging.getLogger("aegis.remediation")

# ─── Helpers ──────────────────────────────────────────────────────────────────

_SAFE_FILENAME_RE = re.compile(r'[^\w.\-]')   # Allow only word chars, dots, hyphens


def _read_sample_df(path: str, fmt: str):  # type: ignore[return]
    """Read sample header row from format to compute column and row counts."""
    import pandas as pd
    try:
        if fmt == "csv":
            return pd.read_csv(path, nrows=100)
        if fmt == "xlsx":
            return pd.read_excel(path, nrows=100)
        if fmt == "json":
            return pd.read_json(path).head(100)
        if fmt == "jsonl":
            return pd.read_json(path, lines=True).head(100)
        if fmt == "parquet":
            import pyarrow.parquet as pq
            return pq.read_table(path).to_pandas().head(100)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not parse sample dataframe for integrity calculation (%s): %s", path, exc)
    return pd.DataFrame()


router = APIRouter(prefix="/api/v1/datasets", tags=["remediation"])


@router.post(
    "/{dataset_id}/remediate",
    response_model=RemediationResponse,
    status_code=status.HTTP_200_OK,
    summary="Remediate dataset threats, generate sanitized artifact, and execute verification re-scan",
)
@limiter.limit("60/minute")
async def remediate_dataset(
    request: Request,
    dataset_id: int,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # API key guard
) -> RemediationResponse:
    # 1. Retrieve dataset record
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if not file_service.sample_exists(record.stored_filename):
        raise HTTPException(status_code=404, detail="Original dataset file not found on disk.")

    # 2. Check if dataset has been scanned first
    if not record.scan_reports:
        raise HTTPException(status_code=400, detail="Dataset must be scanned (/scan) before requesting remediation.")

    latest_report = sorted(record.scan_reports, key=lambda r: r.scanned_at)[-1]
    orig_risk = latest_report.risk_score
    orig_findings_count = latest_report.threats_found_count

    # 3. Execute Sanitizer transformation on existing source (samples/ or quarantine/)
    try:
        orig_source_path = str(file_service.get_existing_source_path(record.stored_filename))
    except (FileNotFoundError, ValueError) as err:
        raise HTTPException(status_code=404, detail="Source file unavailable for remediation.") from err

    # Catch sanitization exceptions, log full traceback, return generic 500 error
    try:
        san_result = await run_in_threadpool(sanitize_file, orig_source_path, record.file_format)
    except Exception as exc:
        logger.exception("Unexpected exception during dataset remediation for dataset_id=%d", dataset_id)
        raise HTTPException(status_code=500, detail="Internal server error during remediation execution.") from exc

    if san_result.error:
        logger.error("Sanitization process failed for dataset %d: %s", dataset_id, san_result.error)
        raise HTTPException(status_code=500, detail="Sanitization failed. Check server logs for details.")

    # 4. Save sanitized file to data/sanitized/ (Original remains untouched)
    san_filename, san_sha256, san_path = file_service.save_sanitized(
        original_stored_filename=record.stored_filename,
        content=san_result.sanitized_bytes,
    )

    # 5. Automated Verification Re-Scan of Sanitized Artifact
    try:
        rescan_result = await run_in_threadpool(run_scan, str(san_path))
    except Exception as exc:
        logger.exception("Re-scan failed during remediation for dataset_id=%d", dataset_id)
        raise HTTPException(status_code=500, detail="Verification re-scan failed during remediation.") from exc

    san_risk = rescan_result.risk_score
    remaining_count = rescan_result.threats_found_count

    # Check actionable threats vs preserved informational research metadata (MAL-009)
    remaining_actionable = [
        f for f in rescan_result.all_findings
        if f.category != "malware_reference" and f.severity not in ("low", "info")
    ]
    orig_actionable = [
        f for f in (latest_report.findings or [])
        if f.get("category") != "malware_reference" and f.get("severity") not in ("low", "info")
    ]

    if len(orig_actionable) > 0:
        reduction_pct = round(
            max(0.0, min(100.0, ((len(orig_actionable) - len(remaining_actionable)) / len(orig_actionable)) * 100.0)),
            1,
        )
    elif orig_risk > 0 and orig_risk > san_risk:
        reduction_pct = round(max(0.0, min(100.0, ((orig_risk - san_risk) / orig_risk) * 100.0)), 1)
    else:
        reduction_pct = 100.0 if len(remaining_actionable) == 0 else 0.0

    resolved_count = max(0, orig_findings_count - len(remaining_actionable))

    # ── Compute data integrity preservation score ──────────────────────────
    import os
    try:
        sample_df = _read_sample_df(orig_source_path, record.file_format)
        _total_cols = max(len(sample_df.columns), 1)
        _file_bytes = os.path.getsize(orig_source_path)
        _est_rows = max(_file_bytes // max(_total_cols * 20, 1), 1)
        _total_fields = _est_rows * _total_cols
        integrity_preserved = round(
            100.0 * (1.0 - san_result.changes_count / max(_total_fields, 1)), 2
        )
        integrity_preserved = max(0.0, min(100.0, integrity_preserved))
    except Exception:  # noqa: BLE001
        integrity_preserved = round(
            100.0 * (1.0 - san_result.changes_count / max(san_result.changes_count + 1000, 1)), 2
        )

    # Determine status: "completed" if 0 remaining actionable threats, else "partial"
    rem_status = "completed" if len(remaining_actionable) == 0 else "partial"

    # Update dataset status in DB
    record.status = "remediated" if rem_status == "completed" else "partial_remediated"
    db.commit()

    # Build action dicts
    action_dicts = [
        {
            "rule_id": a.rule_id,
            "category": a.category,
            "location": a.location,
            "action_taken": a.action_taken,
            "sample_after": a.sample_after,
        }
        for a in san_result.actions
    ]

    # Generate a cryptographically secure download token + record its creation time
    download_token = secrets.token_urlsafe(32)
    token_created_at = datetime.now(UTC)

    # 6. Persist RemediationRecord
    db_record = RemediationRecord(
        dataset_id=record.id,
        original_sha256=record.sha256_hash,
        sanitized_sha256=san_sha256,
        stored_sanitized_filename=san_filename,
        download_token=download_token,
        token_created_at=token_created_at,
        used=False,
        remediation_status=rem_status,
        original_risk_score=orig_risk,
        sanitized_risk_score=san_risk,
        original_findings_count=orig_findings_count,
        remaining_findings_count=remaining_count,
        resolved_findings_count=resolved_count,
        threat_reduction_percent=reduction_pct,
        changes_count=san_result.changes_count,
        integrity_preserved=integrity_preserved,
        remediation_actions_json=json.dumps(action_dicts),
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    action_schemas = [RemediationActionSchema(**a) for a in db_record.actions]

    return RemediationResponse(
        remediation_id=db_record.id,
        dataset_id=db_record.dataset_id,
        original_sha256=db_record.original_sha256,
        sanitized_sha256=db_record.sanitized_sha256,
        download_token=db_record.download_token,
        remediation_status=db_record.remediation_status,
        original_risk_score=db_record.original_risk_score,
        sanitized_risk_score=db_record.sanitized_risk_score,
        original_findings_count=db_record.original_findings_count,
        remaining_findings_count=db_record.remaining_findings_count,
        resolved_findings_count=db_record.resolved_findings_count,
        threat_reduction_percent=db_record.threat_reduction_percent,
        integrity_preserved=integrity_preserved,
        changes_count=db_record.changes_count,
        remediated_at=db_record.remediated_at,
        actions=action_schemas,
    )


@router.get(
    "/{dataset_id}/remediation",
    response_model=RemediationResponse,
    summary="Get the latest remediation report for a dataset",
)
@limiter.limit("60/minute")
def get_remediation_report(
    request: Request,
    dataset_id: int,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # A-014
) -> RemediationResponse:
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if not record.remediations:
        raise HTTPException(status_code=404, detail="No remediation report found. Run /remediate first.")

    latest = sorted(record.remediations, key=lambda r: r.remediated_at)[-1]
    action_schemas = [RemediationActionSchema(**a) for a in latest.actions]

    return RemediationResponse(
        remediation_id=latest.id,
        dataset_id=latest.dataset_id,
        original_sha256=latest.original_sha256,
        sanitized_sha256=latest.sanitized_sha256,
        download_token=latest.download_token if not latest.used else None,
        remediation_status=latest.remediation_status,
        original_risk_score=latest.original_risk_score,
        sanitized_risk_score=latest.sanitized_risk_score,
        original_findings_count=latest.original_findings_count,
        remaining_findings_count=latest.remaining_findings_count,
        resolved_findings_count=latest.resolved_findings_count,
        threat_reduction_percent=latest.threat_reduction_percent,
        integrity_preserved=latest.integrity_preserved,
        changes_count=latest.changes_count,
        remediated_at=latest.remediated_at,
        actions=action_schemas,
    )


@router.get(
    "/{dataset_id}/download-sanitized",
    summary="Download the sanitized dataset file (requires valid download token)",
)
@limiter.limit("60/minute")
def download_sanitized_dataset(
    request: Request,
    dataset_id: int,
    token: str | None = Query(default=None, description="Download token from remediation response"),
    authorization: str | None = Header(default=None, alias="Authorization"),
    db: Session = Depends(get_db),  # noqa: B008
) -> FileResponse:
    """
    Serve the sanitized dataset artifact.
    Accepts token via 'Authorization: Bearer <token>' header OR '?token=...' query parameter.
    """
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if not record.remediations:
        raise HTTPException(status_code=404, detail="No sanitized artifact exists for this dataset.")

    latest = sorted(record.remediations, key=lambda r: r.remediated_at)[-1]

    # Extract token from Authorization header if present ("Bearer <token>")
    provided_token = token
    if authorization and authorization.lower().startswith("bearer "):
        provided_token = authorization.split(" ", 1)[1].strip()

    # FINDING-023: Check single-use status
    if getattr(latest, "used", False):
        raise HTTPException(
            status_code=403,
            detail="Download token has already been used. Re-run remediation to generate a new token.",
        )

    # ── Token validation (constant-time comparison) ──
    expected_token = latest.download_token or ""
    req_token = provided_token or ""
    if not expected_token or not secrets.compare_digest(expected_token, req_token):
        raise HTTPException(
            status_code=403,
            detail="Invalid or missing download token. Re-run remediation to obtain a valid token.",
        )

    # ── FINDING-005: Timezone-safe expiry check ─────────────────────────
    expiry_minutes = settings.download_token_expiry_minutes
    if expiry_minutes > 0 and latest.token_created_at:
        created = latest.token_created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        age = datetime.now(UTC) - created
        if age > timedelta(minutes=expiry_minutes):
            raise HTTPException(
                status_code=403,
                detail=f"Download token expired ({expiry_minutes} min limit). Re-run remediation to get a fresh token.",
            )

    try:
        san_path = file_service.get_sanitized_path(latest.stored_sanitized_filename)
    except ValueError as err:
        raise HTTPException(status_code=403, detail="Invalid path reference.") from err

    if not san_path.exists():
        raise HTTPException(status_code=404, detail="Sanitized file artifact missing from storage.")

    # Mark token as used upon successful download (FINDING-023)
    latest.used = True
    db.commit()

    safe_name = Path(record.original_filename).name
    safe_name = _SAFE_FILENAME_RE.sub("_", safe_name)
    download_name = f"sanitized_{safe_name}"
    mime = record.mime_type or "application/octet-stream"

    # FINDING-028: Rely on filename parameter in FileResponse (no duplicate headers dict)
    return FileResponse(
        path=str(san_path),
        filename=download_name,
        media_type=mime,
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, private"},
    )
