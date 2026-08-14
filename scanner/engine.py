"""
Aegis Node — Multi-Stage Scan Orchestration Engine.

Pipeline:
  Stage 0   → raw_bytes_scan() inside check_file() — EICAR, PE/ELF, NOP sled
  Stage 0.5 → Heuristic scan (entropy, process injection, packers, MIME mismatch…)
  Stage 1   → ClamAV INSTREAM virus scan (graceful fallback if daemon offline)
  Stage 2   → Rule-based content inspection (formula, script, SQL, malware names)

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
    from scanner.heuristics import heuristic_scan
except ImportError:
    from clamd_client import ClamAVResult  # type: ignore[no-redef]
    from clamd_client import scan_file as clamd_scan  # type: ignore[no-redef]
    from content_checker import (  # type: ignore[no-redef]
        ContentCheckResult,
        ContentFinding,
        check_file,
    )
    from heuristics import heuristic_scan  # type: ignore[no-redef]

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

    # Content rules (Stage 0 raw scan + Stage 2 content rules)
    content_findings: list[ContentFinding] = field(default_factory=list)
    rows_inspected: int = 0

    # Heuristic findings (Stage 0.5)
    heuristic_findings: list[ContentFinding] = field(default_factory=list)
    heuristic_risk_score: float = 0.0

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
        # Heuristic findings first (highest-signal for unknown threats)
        for f in self.heuristic_findings:
            out.append({
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "description": f.description,
                "location": f.location,
                "sample": f.sample,
            })
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

    @property
    def all_findings(self) -> list[ContentFinding]:
        """Combined list of heuristic + content findings."""
        return self.heuristic_findings + self.content_findings


def _compute_sha256(path: Path) -> str:
    """Compute SHA-256 hash of a file safely in 64 KB chunks."""
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def _determine_verdict(
    clamav_result: ClamAVResult,
    content_result: ContentCheckResult,
    heur_findings: list[ContentFinding],
    heur_risk: float,
) -> tuple[str, float]:
    """
    Determine final verdict and composite risk score from all pipeline stages.

    Verdict priority:
      malicious  — ClamAV infected, OR critical finding from any stage
      suspicious — high/medium finding from content rules OR significant heuristic risk
      clean      — no threats detected
    """
    # Content-rule base score (0–10 scale from content_checker)
    base_score = content_result.risk_score

    # Add heuristic contribution (heur_risk is 0–1, scale to 0–3 headroom)
    heur_contribution = heur_risk * 3.0
    composite_score = min(base_score + heur_contribution, 10.0)

    # All findings combined for severity checks
    all_findings = content_result.findings + heur_findings

    if clamav_result.infected:
        return "malicious", min(composite_score + 5.0, 10.0)

    if any(f.severity == "critical" for f in all_findings):
        return "malicious", min(composite_score, 10.0)

    if any(f.severity in ("high", "medium") for f in all_findings):
        return "suspicious", min(composite_score, 10.0)

    # Even with no individual critical/high findings, significant heuristic risk
    # alone warrants a suspicious verdict
    if heur_risk >= 0.4:
        return "suspicious", round(composite_score, 2)

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

    # ─── Stage 0.5: Heuristic Scan ───────────────────────────────────────────
    logger.info("Stage 0.5: Heuristic scan for %s", path.name)
    heur_findings, heur_risk = heuristic_scan(file_path)
    result.heuristic_findings = heur_findings
    result.heuristic_risk_score = heur_risk
    if heur_findings:
        logger.warning(
            "Heuristics: %d finding(s), risk=%.4f for %s",
            len(heur_findings), heur_risk, path.name,
        )

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
    result.verdict, result.risk_score = _determine_verdict(clam, content, heur_findings, heur_risk)
    result.threats_found_count = (
        content.threat_count
        + len(heur_findings)
        + (1 if clam.infected else 0)
    )
    result.scan_duration_ms = int((time.monotonic() - start_ms) * 1000)

    logger.info(
        "Scan complete — %s | verdict=%s risk=%.1f threats=%d "
        "(heur=%d content=%d clam=%s) duration=%dms",
        path.name, result.verdict, result.risk_score, result.threats_found_count,
        len(heur_findings), content.threat_count,
        "infected" if clam.infected else "clean",
        result.scan_duration_ms,
    )
    return result

