"""
Aegis Node — Multi-Stage Scan Orchestration Engine.

Pipeline:
  Stage 1 → ClamAV INSTREAM virus scan (graceful fallback if daemon offline)
  Stage 2 → Rule-based content inspection (formula, script, SQL, binary)

Returns a structured ScanEngineResult for persistence and API response.
"""

import hashlib
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

try:
    from scanner.clamd_client import ClamAVResult
    from scanner.clamd_client import scan_file as clamd_scan
    from scanner.content_checker import ContentCheckResult, ContentFinding, check_file
except ImportError:
    from clamd_client import ClamAVResult  # type: ignore[no-redef]
    from clamd_client import scan_file as clamd_scan
    from content_checker import (  # type: ignore[no-redef]
        ContentCheckResult,
        ContentFinding,
        check_file,
    )

logger = logging.getLogger(__name__)

_CLAMAV_HOST = "127.0.0.1"
_CLAMAV_PORT = 3310


@dataclass
class ScanEngineResult:
    # File identity
    file_path: str
    sha256_hash: str

    # ClamAV
    clamav_available: bool = False
    clamav_status: str = "skipped"        # clean | infected | skipped | error
    clamav_virus_name: str | None = None

    # Content rules
    content_findings: list[ContentFinding] = field(default_factory=list)
    rows_inspected: int = 0

    # Aggregated
    threats_found_count: int = 0
    risk_score: float = 0.0
    scan_duration_ms: int = 0
    verdict: str = "clean"                 # clean | suspicious | malicious

    # Parse error from content stage
    content_error: str | None = None

    def to_findings_dicts(self) -> list[dict]:
        """Serialise all findings to a list of dicts for JSON persistence."""
        out = []
        for f in self.content_findings:
            out.append({
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "location": f.location,
                "sample": f.sample,
            })
        if self.clamav_virus_name:
            out.insert(0, {
                "rule_id": "CLAM-001",
                "severity": "critical",
                "category": "clamav",
                "description": f"ClamAV detected: {self.clamav_virus_name}",
                "location": "clamav",
                "sample": self.clamav_virus_name,
            })
        return out


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file safely in 64 KB chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _determine_verdict(clamav_result: ClamAVResult, content_result: ContentCheckResult) -> tuple[str, float]:
    """
    Determine final verdict and composite risk score.
    - malicious: ClamAV infected OR critical content findings
    - suspicious: high/medium content findings only
    - clean: no threats
    """
    base_score = content_result.risk_score

    if clamav_result.infected:
        return "malicious", min(base_score + 5.0, 10.0)

    if any(f.severity == "critical" for f in content_result.findings):
        return "malicious", min(base_score, 10.0)

    if any(f.severity in ("high", "medium") for f in content_result.findings):
        return "suspicious", min(base_score, 10.0)

    return "clean", 0.0


def run_scan(file_path: str, clamav_host: str = _CLAMAV_HOST, clamav_port: int = _CLAMAV_PORT) -> ScanEngineResult:
    """
    Execute the full scan pipeline against a file.
    Always returns a ScanEngineResult regardless of errors.
    """
    start_ms = time.monotonic()
    path = Path(file_path)
    result = ScanEngineResult(file_path=file_path, sha256_hash="")

    # ─── Hash verification ────────────────────────────────────────────────────
    result.sha256_hash = _compute_sha256(path)

    # ─── Stage 1: ClamAV ─────────────────────────────────────────────────────
    logger.info("Stage 1: ClamAV scan for %s", path.name)
    clam: ClamAVResult = clamd_scan(file_path, host=clamav_host, port=clamav_port)
    result.clamav_available = clam.available

    if not clam.available:
        result.clamav_status = "skipped"
        logger.warning("ClamAV offline — skipping virus stage for %s", path.name)
    elif clam.infected:
        result.clamav_status = "infected"
        result.clamav_virus_name = clam.virus_name
        logger.warning("ClamAV: INFECTED — %s in %s", clam.virus_name, path.name)
    else:
        result.clamav_status = "clean"

    # ─── Stage 2: Content Rules ───────────────────────────────────────────────
    logger.info("Stage 2: Content rule inspection for %s", path.name)
    content: ContentCheckResult = check_file(file_path)
    result.content_findings = content.findings
    result.rows_inspected = content.rows_inspected
    result.content_error = content.error

    # ─── Aggregate ────────────────────────────────────────────────────────────
    result.verdict, result.risk_score = _determine_verdict(clam, content)
    result.threats_found_count = content.threat_count + (1 if clam.infected else 0)
    result.scan_duration_ms = int((time.monotonic() - start_ms) * 1000)

    logger.info(
        "Scan complete — %s | verdict=%s risk=%.1f threats=%d duration=%dms",
        path.name, result.verdict, result.risk_score, result.threats_found_count, result.scan_duration_ms,
    )
    return result
