"""
Aegis Node — scan history events (append-only).

Events record what actually ran: a step that never ran gets no event, and a failure
is recorded as a failure. Details are bounded facts (states, counts, verdicts) and
never contain file contents, original filenames, secrets or raw provider payloads.
This is an application history, not a tamper-proof audit log: rows are protected by
the API (no update or delete route), not cryptographically.
"""

import json
import logging

from models import DatasetRecord, ScanEventRecord, ScanReportRecord
from sqlalchemy.orm import Session

logger = logging.getLogger("aegis.history")

EVENT_TYPES = {
    "UPLOAD_ACCEPTED",
    "SCAN_STARTED",
    "DETECTOR_COMPLETED",
    "THREAT_INTEL_LOOKUP_COMPLETED",
    "THREAT_INTEL_LOOKUP_FAILED",
    "SCAN_COMPLETED",
    "SCAN_FAILED",
    "AI_ANALYSIS_STARTED",
    "AI_ANALYSIS_COMPLETED",
    "REMEDIATION_STARTED",
    "VERIFICATION_SCAN_COMPLETED",
    "REMEDIATION_COMPLETED",
    "REMEDIATION_FAILED",
}

_MAX_KEYS = 24
_MAX_STR = 200
_MAX_LIST = 32


def _bounded(value):
    """Keep only JSON primitives (and short lists/dicts of them), truncated."""
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return value[:_MAX_STR]
    if isinstance(value, list | tuple):
        return [_bounded(v) for v in list(value)[:_MAX_LIST]]
    if isinstance(value, dict):
        return {str(k)[:64]: _bounded(v) for k, v in list(value.items())[:_MAX_KEYS]}
    return str(value)[:_MAX_STR]


def record_event(
    db: Session,
    event_type: str,
    *,
    dataset: DatasetRecord | None = None,
    scan: ScanReportRecord | None = None,
    outcome: str = "ok",
    **detail,
) -> ScanEventRecord:
    """Add one event to the session (the caller commits with its own transaction)."""
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown history event type {event_type!r}")
    event = ScanEventRecord(
        dataset_id=dataset.id if dataset is not None else None,
        scan_report_id=scan.id if scan is not None else None,
        event_type=event_type,
        outcome=outcome,
        detail_json=json.dumps(_bounded(detail)),
    )
    db.add(event)
    return event


def _av_reason(error: str | None) -> str | None:
    """Short, non-sensitive reason code for an antivirus stage that gave no result."""
    if not error:
        return None
    if error.startswith("METADEFENDER_HASH_NOT_FOUND"):
        return "METADEFENDER_HASH_NOT_FOUND"
    if "429" in error or "rate limit" in error.lower():
        return "RATE_LIMITED"
    if "auth" in error.lower() or "API key" in error:
        return "AUTH"
    return "UNREACHABLE"


def detector_events(db: Session, dataset: DatasetRecord, scan: ScanReportRecord, result) -> None:
    """One DETECTOR_COMPLETED per local detector, from the engine result and its limitations."""
    limitations = set(result.verification_limitations)

    def state(name: str, ran: bool) -> str:
        if f"DETECTOR_DISABLED:{name}" in limitations:
            return "disabled"
        if f"DETECTOR_UNAVAILABLE:{name}" in limitations:
            return "unavailable"
        return "ran" if ran else "unavailable"

    record_event(db, "DETECTOR_COMPLETED", dataset=dataset, scan=scan, detector="clamav",
                 state={"clean": "ran", "infected": "ran"}.get(result.clamav_status, "unavailable"),
                 clamav_status=result.clamav_status, provider=scan.av_provider,
                 reason=_av_reason(getattr(result, "clamav_error", None)))
    record_event(db, "DETECTOR_COMPLETED", dataset=dataset, scan=scan, detector="yara",
                 state=state("yara", result.yara_available), findings=len(result.yara_findings))
    record_event(db, "DETECTOR_COMPLETED", dataset=dataset, scan=scan, detector="heuristics",
                 state=state("heuristics", True), findings=len(result.heuristic_findings))
    record_event(db, "DETECTOR_COMPLETED", dataset=dataset, scan=scan, detector="content_rules",
                 state="ran" if not result.content_error else "incomplete",
                 findings=len(result.content_findings), coverage_status=result.coverage_status,
                 rows_inspected=result.rows_inspected, rows_total=result.rows_total)


def threat_intel_events(db: Session, dataset: DatasetRecord, scan: ScanReportRecord, ti_report) -> None:
    """Per configured provider: how many lookups ran and with which result states."""
    if ti_report is None:
        return
    for provider in ti_report.providers_checked:
        items = [e for e in ti_report.evidence if e.provider == provider]
        if not items:
            continue  # configured, but nothing of its indicator type was found: not queried
        states: dict[str, int] = {}
        for e in items:
            states[e.result_state] = states.get(e.result_state, 0) + 1
        failed = any(e.error_status for e in items)
        record_event(
            db,
            "THREAT_INTEL_LOOKUP_FAILED" if failed else "THREAT_INTEL_LOOKUP_COMPLETED",
            dataset=dataset, scan=scan, outcome="failed" if failed else "ok",
            provider=provider, lookups=len(items), result_states=states,
            indicator_types=sorted({e.indicator_type for e in items}),
        )
