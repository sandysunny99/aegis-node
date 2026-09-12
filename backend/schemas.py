"""
Aegis Node — Pydantic API Schemas.
Defines request/response models used by the REST API layer.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# ─── Upload ───────────────────────────────────────────────────────────────────

class DatasetUploadResponse(BaseModel):
    """Returned after a successful dataset file upload."""
    dataset_id: int
    original_filename: str
    stored_filename: str
    file_size_bytes: int
    sha256_hash: str
    mime_type: str
    file_format: str
    status: str
    uploaded_at: datetime


# ─── Scan Findings ────────────────────────────────────────────────────────────

class ThreatIntelResult(BaseModel):
    provider: str
    indicator_type: str
    indicator: str
    status: str
    confidence: str | None = None
    first_seen: str | None = None
    tags: list[str] = []
    source: str
    malicious_count: int | None = None
    suspicious_count: int | None = None
    harmless_count: int | None = None
    undetected_count: int | None = None
    raw_reference: str | None = None
    error_message: str | None = None

class NormalizedTIEvidence(BaseModel):
    provider: str
    indicator_type: str
    indicator: str
    reputation: str = Field(..., description="malicious | suspicious | benign | unknown")
    confidence: str | None = None
    severity: str = Field(..., description="critical | high | medium | low | informational")
    category: str | None = None
    source_timestamp: str | None = None
    observed_at: datetime | None = None
    reference_url: str | None = None
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    error_status: str | None = None

class TIFusionReport(BaseModel):
    status: str = Field(..., description="active | degraded | disabled | error")
    evidence: list[NormalizedTIEvidence] = []
    evidence_strength: str = Field(..., description="NONE | SINGLE_PROVIDER | CORROBORATED | CONFLICTED | PROVIDER_UNAVAILABLE")
    providers_checked: list[str] = []
    limitations: list[str] = []
    conflicts: list[str] = []

class ThreatFinding(BaseModel):
    """A single threat or anomaly detected during scanning."""
    rule_id: str = Field(..., description="Unique identifier for the detection rule")
    severity: str = Field(..., description="critical | high | medium | low")
    category: str = Field(..., description="formula_injection | script_injection | sql_injection | binary_anomaly | clamav | threat_intel")
    description: str
    location: str = Field(..., description="Column name, byte offset, or 'clamav'")
    sample: str = Field(default="", description="Truncated sample of the offending content (max 200 chars)")


# ─── Scan Result ─────────────────────────────────────────────────────────────

class ScanResultResponse(BaseModel):
    """Returned after a scan is completed."""
    scan_id: int
    dataset_id: int
    clamav_status: str
    clamav_virus_name: str | None
    threats_found_count: int
    risk_score: float = Field(..., description="Composite risk score 0.0 – 10.0")
    scan_duration_ms: int
    scanned_at: datetime
    verdict: str = Field(..., description="clean_verified | clean_with_limitations | suspicious | malicious | scan_incomplete")
    rows_inspected: int = 0
    rows_total: int | None = None
    coverage_percentage: float = 100.0
    coverage_status: str = "FULL"
    verification_limitations: list[str] = Field(default_factory=list)
    findings: list[ThreatFinding]
    threat_intel: TIFusionReport | None = None


# ─── Dataset Status ───────────────────────────────────────────────────────────

class DatasetStatusResponse(BaseModel):
    """Lightweight status check for a dataset."""
    dataset_id: int
    original_filename: str
    file_size_bytes: int
    sha256_hash: str
    status: str
    uploaded_at: datetime


# ─── LLM Analysis Response ───────────────────────────────────────────────────

class AnalysisResponse(BaseModel):
    analysis_id: int | None = None
    dataset_id: int
    model_name: str
    status: str = Field(..., description="completed | failed | unavailable")
    verdict: str = Field(..., description="clean | suspicious | high_risk | inconclusive")
    severity: str = Field(..., description="low | medium | high | critical | unknown")
    confidence: float = Field(..., ge=0.0, le=1.0, description="AI confidence rating 0.0 - 1.0")
    summary: str
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    
    # Observability Fields
    guardrail_status: str = "N/A"
    guardrail_score: float | None = None
    guardrail_signals: list[str] = Field(default_factory=list)
    llm_invoked: bool = False
    llm_bypassed: bool = False
    llm_context_mode: str = "UNKNOWN"
    
    prompt_tokens: int = 0
    completion_tokens: int = 0
    created_at: datetime
    error: str | None = None


# ─── Remediation Schemas ──────────────────────────────────────────────────────

class RemediationActionSchema(BaseModel):
    rule_id: str
    category: str
    location: str
    action_taken: str
    sample_after: str = ""


class RemediationResponse(BaseModel):
    remediation_id: int
    dataset_id: int
    original_sha256: str
    sanitized_sha256: str
    download_token: str | None = Field(default=None, description="One-time secure token required for downloading the sanitized file")
    remediation_status: str = Field(..., description="completed | partial | failed")
    original_risk_score: float
    sanitized_risk_score: float
    original_findings_count: int
    remaining_findings_count: int
    resolved_findings_count: int
    threat_reduction_percent: float
    integrity_preserved: float = Field(default=100.0, description="Percentage of dataset fields unchanged after sanitization")
    changes_count: int
    remediated_at: datetime
    actions: list[RemediationActionSchema] = Field(default_factory=list)
    error: str | None = None


# ─── Error Response ───────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    detail: str
    code: str = "error"
    extra: dict[str, Any] | None = None
