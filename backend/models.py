"""
Aegis Node — SQLAlchemy ORM Models.
Defines the core tables: DatasetRecord, ScanReportRecord, LlmAnalysisRecord, RemediationRecord.
"""

import json
from datetime import UTC, datetime

from database import Base
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship


def _now() -> datetime:
    return datetime.now(UTC)


class DatasetRecord(Base):
    """Represents a dataset file uploaded for scanning."""

    __tablename__ = "datasets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    original_filename: Mapped[str] = mapped_column(String(512), nullable=False)
    stored_filename: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    mime_type: Mapped[str] = mapped_column(String(128), nullable=False, default="application/octet-stream")
    file_format: Mapped[str] = mapped_column(String(32), nullable=False, default="unknown")
    uploaded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())
    # status: uploaded | scanning | clean | quarantined | suspicious | remediated | partial_remediated | error
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

    def __repr__(self) -> str:
        return f"<DatasetRecord id={self.id} file={self.original_filename!r} status={self.status!r}>"


class ScanReportRecord(Base):
    """Stores the full scan report for a dataset scan execution."""

    __tablename__ = "scan_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    dataset_id: Mapped[int] = mapped_column(Integer, ForeignKey("datasets.id"), nullable=False, index=True)

    # ClamAV stage
    clamav_status: Mapped[str] = mapped_column(String(64), nullable=False, default="skipped")
    clamav_virus_name: Mapped[str] = mapped_column(String(256), nullable=True)

    # Content rule stage
    threats_found_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    verdict: Mapped[str] = mapped_column(String(32), nullable=False, default="clean")

    # Timing
    scan_duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    scanned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())

    # Full findings stored as JSON text
    findings_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    dataset: Mapped["DatasetRecord"] = relationship("DatasetRecord", back_populates="scan_reports")

    @property
    def findings(self) -> list[dict]:
        """Deserialise findings JSON to Python list."""
        return json.loads(self.findings_json)

    def __repr__(self) -> str:
        return (
            f"<ScanReportRecord id={self.id} dataset_id={self.dataset_id} "
            f"verdict={self.verdict!r} risk={self.risk_score:.1f} threats={self.threats_found_count}>"
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

    # Metrics
    prompt_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completion_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())

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

    # Secure one-time download token — generated on remediation, required for download
    download_token: Mapped[str] = mapped_column(String(64), unique=True, nullable=True, index=True)
    # Timestamp when the token was generated — used to enforce expiry (default 60 min)
    token_created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True, default=None)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    remediation_status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")  # completed | partial | failed

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
    remediation_actions_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    remediated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_now, server_default=func.now())

    dataset: Mapped["DatasetRecord"] = relationship("DatasetRecord", back_populates="remediations")

    @property
    def actions(self) -> list[dict]:
        return json.loads(self.remediation_actions_json)

    def __repr__(self) -> str:
        return (
            f"<RemediationRecord id={self.id} dataset_id={self.dataset_id} "
            f"status={self.remediation_status!r} reduction={self.threat_reduction_percent:.1f}%>"
        )
