"""
Aegis Node — Dataset REST API Router.
Endpoints: upload, scan, status, report.
"""

import json
import sys
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
from limiter import limiter  # noqa: E402
from models import DatasetRecord, ScanReportRecord  # noqa: E402
from schemas import (  # noqa: E402
    DatasetStatusResponse,
    DatasetUploadResponse,
    ScanResultResponse,
    ThreatFinding,
)
from services.file_service import file_service, validate_magic_bytes  # noqa: E402
from sqlalchemy import update  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from utils.auth import require_api_key  # noqa: E402
from utils.turnstile import verify_turnstile_token  # noqa: E402

from scanner.engine import run_scan  # noqa: E402

router = APIRouter(prefix="/api/v1/datasets", tags=["datasets"])

# ─── Limits ───────────────────────────────────────────────────────────────────
_MAX_UPLOAD_BYTES = 500 * 1024 * 1024  # 500 MB (matches MAX_UPLOAD_SIZE_MB in config)
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
    client_ip = request.headers.get("cf-connecting-ip") or (request.client.host if request.client else None)
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
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=msg,
        )

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
async def scan_dataset(
    request: Request,
    dataset_id: int,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # API key guard
) -> ScanResultResponse:
    # Retrieve dataset record
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if not file_service.sample_exists(record.stored_filename, record.object_key):
        raise HTTPException(status_code=404, detail="Dataset file not found on disk or storage backend.")

    # Guard against concurrent double-scan: atomic UPDATE WHERE status != 'scanning' (A-003)
    updated = db.execute(
        update(DatasetRecord)
        .where(DatasetRecord.id == dataset_id, DatasetRecord.status != "scanning")
        .values(status="scanning")
    )
    db.commit()
    if updated.rowcount == 0:
        raise HTTPException(status_code=409, detail="Scan already in progress for this dataset. Please wait.")

    # FINDING-025: Guard against re-scanning already remediated datasets
    db.refresh(record)
    if record.status == "scanning" and (record.remediations or record.status in ("remediated", "partial_remediated")):
        # Reset status since we set it to scanning atomically
        record.status = "error"
        db.commit()
        raise HTTPException(
            status_code=409,
            detail="Dataset has already been remediated. Re-scanning original is not permitted.",
        )

    # FINDING-011: Wrap blocking scan in try/except; reset status to 'error' on failure
    file_path = str(file_service.get_sample_path(record.stored_filename, record.object_key))
    try:
        result = await run_in_threadpool(run_scan, file_path)
    except Exception as exc:
        record.status = "error"
        db.commit()
        raise HTTPException(status_code=500, detail="Scan execution failed") from exc

    # Phase 9.1: External Threat Intelligence (VirusTotal Hash-First)
    try:
        from services.threat_intelligence.virustotal import lookup_file_hash
        from scanner.content_checker import ContentFinding

        vt_intel = await lookup_file_hash(result.sha256_hash)

        # Append VT result as a threat finding to preserve provenance and evidence without altering DB schema
        severity = "low"
        if vt_intel.status == "malicious":
            severity = "critical"
            # Flag conflict if local scanner thought it was clean
            if result.verdict in ("clean_verified", "clean_with_limitations"):
                result.verification_limitations.append("CONFLICT_VT_MALICIOUS")
        elif vt_intel.status == "suspicious":
            severity = "high"
        elif vt_intel.status in ("timeout", "rate_limited", "provider_error"):
            severity = "low"
            result.verification_limitations.append(f"VT_UNAVAILABLE_{vt_intel.status.upper()}")

        finding = ContentFinding(
            rule_id=f"vt_{vt_intel.status}",
            severity=severity,
            category="threat_intel",
            description=f"VirusTotal {vt_intel.status.upper()} (Confidence: {vt_intel.confidence or 'N/A'}) - {vt_intel.error_message or 'No errors'}",
            location="virustotal",
            sample=vt_intel.raw_reference or ""
        )
        result.content_findings.append(finding)

        # We deliberately do NOT override result.verdict here.
        # "Do not silently change the local scanner finding. The existing evidence-fusion/policy architecture must remain responsible for final interpretation."
    except Exception as ti_exc:
        import logging
        logging.getLogger(__name__).warning(f"Threat intel integration failed: {ti_exc}")
        result.verification_limitations.append("THREAT_INTEL_FAILURE")

    # Phase 9.2: URLhaus
    try:
        from services.threat_intelligence.urlhaus import lookup_url
        import re
        from pathlib import Path

        # Safe URL extraction from raw bytes
        # Using a simple regex to find all HTTP/HTTPS URLs in the file
        raw_bytes = Path(file_path).read_bytes()
        url_pattern = re.compile(rb'https?://[a-zA-Z0-9.-]+(?:/[^\s\"\'<>]*)?', re.IGNORECASE)
        extracted_urls = set()
        for match in url_pattern.finditer(raw_bytes):
            try:
                url_str = match.group().decode('utf-8')
                extracted_urls.add(url_str)
            except Exception:
                pass

        # Limit the number of URLs to lookup to avoid rate limits / long processing times
        # URLhaus allows some queries, but we shouldn't spam it. Limit to 5 unique URLs per scan.
        for url in list(extracted_urls)[:5]:
            urlhaus_intel = await lookup_url(url)

            if urlhaus_intel.status == "unconfigured":
                continue

            severity = "low"
            if urlhaus_intel.status == "malicious":
                severity = "critical"
                if result.verdict in ("clean_verified", "clean_with_limitations"):
                    result.verification_limitations.append("CONFLICT_URLHAUS_MALICIOUS")
            elif urlhaus_intel.status in ("timeout", "rate_limited", "provider_error"):
                severity = "low"
                result.verification_limitations.append(f"URLHAUS_UNAVAILABLE_{urlhaus_intel.status.upper()}")

            finding = ContentFinding(
                rule_id=f"urlhaus_{urlhaus_intel.status}",
                severity=severity,
                category="threat_intel",
                description=f"URLhaus {urlhaus_intel.status.upper()} for URL: {url} - {urlhaus_intel.error_message or 'No errors'}",
                location="urlhaus",
                sample=urlhaus_intel.raw_reference or ""
            )
            result.content_findings.append(finding)

    except Exception as urlhaus_exc:
        import logging
        logging.getLogger(__name__).warning(f"URLhaus integration failed: {urlhaus_exc}")
        result.verification_limitations.append("URLHAUS_FAILURE")

    # Phase 9.3: AbuseIPDB
    try:
        from services.threat_intelligence.abuseipdb import lookup_ip
        import re
        from pathlib import Path

        raw_bytes = Path(file_path).read_bytes()
        ip_pattern = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        extracted_ips = set()
        for match in ip_pattern.finditer(raw_bytes):
            try:
                ip_str = match.group().decode('utf-8')
                extracted_ips.add(ip_str)
            except Exception:
                pass

        for ip in list(extracted_ips)[:5]:
            ip_intel = await lookup_ip(ip)

            if ip_intel.status in ("unconfigured", "invalid_ip"):
                continue

            severity = "low"
            if ip_intel.status == "malicious":
                severity = "critical"
                if result.verdict in ("clean_verified", "clean_with_limitations"):
                    result.verification_limitations.append("CONFLICT_ABUSEIPDB_MALICIOUS")
            elif ip_intel.status == "suspicious":
                severity = "high"
            elif ip_intel.status in ("timeout", "rate_limited", "provider_error"):
                severity = "low"
                result.verification_limitations.append(f"ABUSEIPDB_UNAVAILABLE_{ip_intel.status.upper()}")

            finding = ContentFinding(
                rule_id=f"abuseipdb_{ip_intel.status}",
                severity=severity,
                category="threat_intel",
                description=f"AbuseIPDB {ip_intel.status.upper()} for IP: {ip} (Confidence: {ip_intel.confidence}) - {ip_intel.error_message or 'No errors'}",
                location="abuseipdb",
                sample=ip_intel.raw_reference or ""
            )
            result.content_findings.append(finding)

    except Exception as abuseipdb_exc:
        import logging
        logging.getLogger(__name__).warning(f"AbuseIPDB integration failed: {abuseipdb_exc}")
        result.verification_limitations.append("ABUSEIPDB_FAILURE")

    # Update status
    if result.verdict == "malicious":
        record.status = "quarantined"
        file_service.quarantine(record.stored_filename)
    elif result.verdict == "suspicious":
        record.status = "suspicious"
    else:
        record.status = "clean"
    db.commit()

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
        verdict=report.verdict,
        rows_inspected=report.rows_inspected,
        rows_total=report.rows_total,
        coverage_percentage=report.coverage_percentage,
        coverage_status=report.coverage_status,
        verification_limitations=report.verification_limitations,
        findings=findings,
    )


# ─── Status ───────────────────────────────────────────────────────────────────

@router.get(
    "/{dataset_id}",
    response_model=DatasetStatusResponse,
    summary="Get dataset upload status",
)
@limiter.limit("60/minute")
def get_dataset_status(
    request: Request,
    dataset_id: int,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # A-014
) -> DatasetStatusResponse:
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")
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
@limiter.limit("60/minute")
def get_scan_report(
    request: Request,
    dataset_id: int,
    db: Session = Depends(get_db),  # noqa: B008
    _auth: None = Depends(require_api_key),  # noqa: B008  # A-014
) -> ScanResultResponse:
    record: DatasetRecord | None = db.get(DatasetRecord, dataset_id)
    if not record:
        raise HTTPException(status_code=404, detail="Resource not found.")

    if not record.scan_reports:
        raise HTTPException(status_code=404, detail="No scan report found. Run /scan first.")

    report: ScanReportRecord = sorted(record.scan_reports, key=lambda r: r.scanned_at)[-1]
    findings = [ThreatFinding(**f) for f in report.findings]

    # FINDING-018: Use stored verdict from ScanReportRecord if available
    verdict = getattr(report, "verdict", None)
    if not verdict:
        verdict_map = {"quarantined": "malicious", "suspicious": "suspicious", "clean": "clean_verified"}
        verdict = verdict_map.get(record.status, "clean_verified")

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
        rows_inspected=getattr(report, "rows_inspected", 0),
        rows_total=getattr(report, "rows_total", None),
        coverage_percentage=getattr(report, "coverage_percentage", 100.0),
        coverage_status=getattr(report, "coverage_status", "FULL"),
        verification_limitations=report.verification_limitations,
        findings=findings,
    )
