"""
Aegis Node — SQLAlchemy ORM Models.
Defines the core tables: DatasetRecord, ScanReportRecord, LlmAnalysisRecord, RemediationRecord.
"""

import json
import uuid
from datetime import UTC, datetime

from database import Base
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def _now() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator):
    """
    DateTime that always comes back timezone-aware in UTC. SQLite stores no offset, so
    naive values would reach the API without one and browsers would read UTC as local
    time. Values are written in UTC; naive values read back are UTC.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is not None:
            value = value.astimezone(UTC)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value


def new_public_id() -> str:
    """Unguessable external identifier for a dataset (S1: no sequential IDs in the API)."""
    return uuid.uuid4().hex


class DatasetRecord(Base):
    """Represents a dataset file uploaded for scanning."""

    __tablename__ = "datasets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # Public identifier used in every API path/response; integer `id` stays internal.
    public_id: Mapped[str] = mapped_column(
        String(32), unique=True, index=True, nullable=False, default=new_public_id
    )
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False, default="application/octet-stream")
    file_format: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    storage_backend: Mapped[str] = mapped_column(String(32), nullable=False, default="local")
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_now, server_default=func.now())
    # status: uploaded | scanning | clean | clean_limited | incomplete | quarantined | suspicious
    #         | remediated | partial_remediated | remediated_unverified | error
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="uploaded")

    scan_reports: Mapped[list["ScanReportRecord"]] = relationship(
        "ScanReportRecord", back_populates="dataset", cascade="all, delete-orphan"
    )
    llm_analyses: Mapped[list["LlmAnalysisRecord"]] = relationship(
        "LlmAnalysisRecord", back_populates="dataset", cascade="all, delete-orphan"
    )
    remediations: Mapped[list["RemediationRecord"]] = relationship(
        "RemediationRecord", back_populates="dataset", cascade="all, delete-orphan"
    )

    @property
    def original_scan_reports(self) -> list["ScanReportRecord"]:
        """Scans of the uploaded file, oldest first; excludes remediation re-scans."""
        reports = [r for r in self.scan_reports if r.scan_target == "original"]
        return sorted(reports, key=lambda r: r.scanned_at)

    @property
    def latest_scan_report(self) -> "ScanReportRecord | None":
        """Most recent scan of the uploaded file, or None if it was never scanned."""
        reports = self.original_scan_reports
        return reports[-1] if reports else None

    def __repr__(self) -> str:
        return f"<DatasetRecord id={self.id} file={self.original_filename!r} status={self.status!r}>"


class ScanReportRecord(Base):
    """Stores the full scan report for a dataset scan execution."""

    __tablename__ = "scan_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # Unguessable id used by the history API; the integer id stays internal.
    public_id: Mapped[str] = mapped_column(
        String(32), unique=True, index=True, nullable=False, default=new_public_id
    )
    dataset_id: Mapped[int] = mapped_column(Integer, ForeignKey("datasets.id"), nullable=False, index=True)
    # When the scan began; scanned_at below is when it finished. Null on rows older than history.
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime(), nullable=True)
    # Deployment profile and AV provider in effect for this scan (null on older rows).
    profile: Mapped[str | None] = mapped_column(String(16), nullable=True)
    av_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # ClamAV stage
    clamav_status: Mapped[str] = mapped_column(String(64), nullable=False, default="skipped")
    clamav_virus_name: Mapped[str] = mapped_column(String(256), nullable=True)

    # Content rule & coverage stage
    threats_found_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="clean_verified")
    rows_inspected: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    rows_total: Mapped[int] = mapped_column(Integer, nullable=True)
    coverage_percentage: Mapped[float] = mapped_column(Float, nullable=False, default=100.0)
    coverage_status: Mapped[str] = mapped_column(String(32), nullable=False, default="FULL")

    # Timing
    scan_duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scanned_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_now, server_default=func.now())

    # Full findings and limitations stored as JSON text
    findings_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    verification_limitations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    threat_intel_json: Mapped[str] = mapped_column(Text, nullable=False, default='{"status":"disabled","evidence":[],"evidence_strength":"NONE","providers_checked":[],"limitations":[],"conflicts":[]}')
    # "original" = scan of the uploaded file; "sanitized" = verification re-scan of a
    # remediated copy (linked from RemediationRecord.rescan_report_id).
    scan_target: Mapped[str] = mapped_column(
        String(16), nullable=False, default="original", server_default="original"
    )

    dataset: Mapped["DatasetRecord"] = relationship("DatasetRecord", back_populates="scan_reports")

    @property
    def findings(self) -> list[dict]:
        """Deserialise findings JSON to Python list."""
        return json.loads(self.findings_json)

    @property
    def verification_limitations(self) -> list[str]:
        """Deserialise limitations JSON to Python list."""
        try:
            return json.loads(self.verification_limitations_json)
        except Exception:
            return []

    @property
    def threat_intel(self) -> dict:
        """Deserialise TI JSON to Python dict."""
        try:
            return json.loads(self.threat_intel_json)
        except Exception:
            return {"status":"error","evidence":[],"evidence_strength":"NONE","providers_checked":[],"limitations":[],"conflicts":[]}

    def __repr__(self) -> str:
        return (
            f"<ScanReportRecord id={self.id} dataset_id={self.dataset_id} "
            f"verdict={self.verdict!r} risk={self.risk_score:.1f} threats={self.threats_found_count} "
            f"coverage={self.coverage_percentage:.1f}%>"
        )


class LlmAnalysisRecord(Base):
    """Stores an AI-generated threat contextual analysis produced by Gemini downstream of scanner."""

    __tablename__ = "llm_analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    dataset_id: Mapped[int] = mapped_column(Integer, ForeignKey("datasets.id"), nullable=False, index=True)
    scan_report_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_reports.id"), nullable=True)

    # Model and Status
    model_name: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")  # completed | failed | unavailable

    # Structured Output Fields
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="inconclusive")  # clean | suspicious | high_risk | inconclusive
    severity: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")  # low | medium | high | critical | unknown
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)  # 0.0 to 1.0

    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    evidence_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    recommendations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    limitations_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Guardrail and Context Status
    guardrail_status: Mapped[str] = mapped_column(String(32), nullable=False, default="N/A")
    guardrail_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    guardrail_signals_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    llm_invoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    llm_bypassed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    llm_context_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="UNKNOWN")

    # Observability and Provider Fallback Fields
    llm_mode: Mapped[str] = mapped_column(String(32), nullable=False, default="auto")
    requested_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    requested_model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    initial_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    final_provider: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    fallback_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    fallback_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    provider_attempts_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    # Metrics
    prompt_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_now, server_default=func.now())

    dataset: Mapped["DatasetRecord"] = relationship("DatasetRecord", back_populates="llm_analyses")

    @property
    def evidence(self) -> list[str]:
        return json.loads(self.evidence_json)

    @property
    def recommendations(self) -> list[str]:
        return json.loads(self.recommendations_json)

    @property
    def limitations(self) -> list[str]:
        return json.loads(self.limitations_json)

    @property
    def guardrail_signals(self) -> list[str]:
        try:
            return json.loads(self.guardrail_signals_json)
        except Exception:
            return []

    @property
    def provider_attempts(self) -> list[dict]:
        try:
            return json.loads(self.provider_attempts_json)
        except Exception:
            return []

    def __repr__(self) -> str:
        return f"<LlmAnalysisRecord id={self.id} dataset_id={self.dataset_id} model={self.model_name!r} status={self.status!r}>"


class RemediationRecord(Base):
    """Stores the execution record and verification metrics of a dataset remediation."""

    __tablename__ = "remediations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    dataset_id: Mapped[int] = mapped_column(Integer, ForeignKey("datasets.id"), nullable=False, index=True)

    original_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    sanitized_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    stored_sanitized_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    object_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    storage_backend: Mapped[str] = mapped_column(String(32), nullable=False, default="local")

    # Secure one-time download token — generated on remediation, required for download
    download_token: Mapped[str] = mapped_column(String(64), unique=True, nullable=True, index=True)
    # Timestamp when the token was generated — used to enforce expiry (default 60 min)
    token_created_at: Mapped[datetime] = mapped_column(UTCDateTime(), nullable=True, default=None)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    remediation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")  # completed | partial | unverified | failed

    original_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    sanitized_risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    original_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    remaining_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    resolved_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threat_reduction_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    changes_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Percentage of dataset fields left unchanged after sanitization (0–100)
    # Stored so GET /remediation can return the real value (not a default).
    integrity_preserved: Mapped[float] = mapped_column(Float, nullable=False, default=100.0)
    # C11: "exact_rows" or "estimated_rows" — how the field count behind the score was obtained
    integrity_method: Mapped[str] = mapped_column(String(16), nullable=False, default="estimated_rows")
    remediation_actions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    # Verification re-scan of the sanitized copy (a ScanReportRecord with scan_target="sanitized")
    rescan_report_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("scan_reports.id"), nullable=True)
    rescan_report: Mapped["ScanReportRecord | None"] = relationship("ScanReportRecord")

    remediated_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_now, server_default=func.now())

    dataset: Mapped["DatasetRecord"] = relationship("DatasetRecord", back_populates="remediations")

    @property
    def actions(self) -> list[dict]:
        return json.loads(self.remediation_actions_json)

    def __repr__(self) -> str:
        return (
            f"<RemediationRecord id={self.id} dataset_id={self.dataset_id} "
            f"status={self.remediation_status!r} reduction={self.threat_reduction_percent:.1f}%>"
        )


class ScanEventRecord(Base):
    """
    Append-only history event (upload, scan steps, threat intel, AI, remediation).

    Written only by services/history.py through the normal API flow; never updated.
    `detail_json` holds small, bounded facts (states, counts, verdicts), never file
    contents, original filenames, secrets or raw provider payloads.
    """

    __tablename__ = "scan_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    dataset_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("datasets.id"), nullable=True, index=True)
    scan_report_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("scan_reports.id"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="ok")  # ok | failed
    detail_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(), default=_now, server_default=func.now(), index=True
    )

    scan_report: Mapped["ScanReportRecord | None"] = relationship("ScanReportRecord")

    @property
    def detail(self) -> dict:
        try:
            return json.loads(self.detail_json)
        except ValueError:
            return {}
