"""
Aegis Node — Stage 0.5: Signature-Less Heuristic Malware Detection.

Analyses raw file bytes using static heuristics to detect obfuscated or
unknown malware that may evade signature-based scanners (ClamAV).

Detection Heuristics
--------------------
HEUR-001  High file entropy (possible packing / encryption / obfuscation)
HEUR-002  High non-printable byte ratio (binary payload in text-expected file)
HEUR-003  Process injection API strings (CreateRemoteThread, WriteProcessMemory…)
HEUR-004  Script-based downloader strings (powershell -enc, IEX, DownloadString…)
HEUR-005  Embedded PE header (MZ+PE magic found past file start — polyglot)
HEUR-006  Packer / protector section names (.UPX0, .aspack, .petite, .fsg…)
HEUR-007  MIME type / extension mismatch (file magic disagrees with extension)
HEUR-008  Dense base64 block with high entropy (encoded payload)

Performance
-----------
Only the first _MAX_BYTES (1 MB) are read for expensive operations.
Files below _MIN_BYTES (64 B) skip all heuristics.

Integration
-----------
Exposes a single entry-point:
    heuristic_scan(file_path: str) -> tuple[list[ContentFinding], float]

The returned findings share the exact ContentFinding dataclass used by
content_checker.py so they plug directly into ScanEngineResult.

Disable with env var: ENABLE_HEURISTICS=false
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from pathlib import Path

logger = logging.getLogger(__name__)

# ── Tuneable limits ────────────────────────────────────────────────────────────
_MAX_BYTES: int = 1_048_576   # 1 MB — max bytes read for heuristics
_MIN_BYTES: int = 64          # files smaller than this are skipped
_ENTROPY_HIGH: float = 7.2    # Shannon entropy threshold (max 8.0 for bytes)
_ENTROPY_MEDIUM: float = 6.5  # medium-entropy warning threshold
_NON_PRINTABLE_RATIO: float = 0.70  # flag if >70 % of bytes are non-printable
_B64_MIN_LEN: int = 80        # minimum consecutive base64 chars to flag
_B64_ENTROPY_THRESHOLD: float = 4.5

# ── Pattern compilations (done once at import) ────────────────────────────────
_PROCESS_INJECTION_BYTES = re.compile(
    rb"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|"
    rb"NtUnmapViewOfSection|RtlCreateUserThread|SetWindowsHookEx|"
    rb"QueueUserAPC|OpenProcess|VirtualProtect",
    re.IGNORECASE,
)

_DOWNLOADER_BYTES = re.compile(
    rb"powershell\s+-[Ee]nc|"
    rb"cmd\.exe\s+/[cC]|"
    rb"IEX\s*\(|Invoke-Expression|"
    rb"Net\.WebClient|DownloadString|DownloadFile|"
    rb"bitsadmin|certutil\s+-decode|"
    rb"wget\s+http|curl\s+-[oO]",
    re.IGNORECASE,
)

_PACKER_SECTIONS = re.compile(
    rb"\.UPX0|\.UPX1|\.UPX2|"
    rb"\.aspack|\.adata|"
    rb"\.petite|"
    rb"\.fsg|"
    rb"\.MPRESS1|\.MPRESS2|"
    rb"\.themida|\.winlicense|"
    rb"\.nsp0|\.nsp1|\.nsp2",
)

_B64_BLOCK = re.compile(rb"[A-Za-z0-9+/]{" + str(_B64_MIN_LEN).encode() + rb",}={0,2}")

# Printable ASCII range 0x20–0x7E plus common whitespace
_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


# ── Try to import optional dependencies ───────────────────────────────────────
try:
    import magic as _magic         # python-magic (libmagic wrapper)
    _HAS_MAGIC = True
except ImportError:               # pragma: no cover
    _HAS_MAGIC = False

try:
    import pefile as _pefile       # PE analysis
    _HAS_PEFILE = True
except ImportError:               # pragma: no cover
    _HAS_PEFILE = False


# ── ContentFinding import — mirror engine.py's dual-path import ───────────────
try:
    from scanner.content_checker import ContentFinding
except ImportError:
    from content_checker import ContentFinding  # type: ignore[no-redef]


# ─────────────────────────────────────────────────────────────────────────────
# Core Heuristic Functions
# ─────────────────────────────────────────────────────────────────────────────

def calculate_entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq = Counter(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _non_printable_ratio(data: bytes) -> float:
    """Fraction of bytes that are not printable ASCII or common whitespace."""
    if not data:
        return 0.0
    non_print = sum(1 for b in data if b not in _PRINTABLE)
    return non_print / len(data)


def _make_finding(
    rule_id: str,
    severity: str,
    description: str,
    location: str = "raw_bytes",
    sample: str = "",
) -> ContentFinding:
    return ContentFinding(
        rule_id=rule_id,
        severity=severity,
        category="heuristic_malware",
        description=description,
        location=location,
        sample=sample,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Individual Heuristic Checks
# ─────────────────────────────────────────────────────────────────────────────

def _check_entropy(data: bytes, file_size: int) -> list[ContentFinding]:
    """HEUR-001 — High Shannon entropy (packing / encryption / obfuscation)."""
    findings: list[ContentFinding] = []
    entropy = calculate_entropy(data)

    if entropy >= _ENTROPY_HIGH:
        findings.append(_make_finding(
            "HEUR-001", "high",
            f"File entropy is {entropy:.2f}/8.00 (threshold {_ENTROPY_HIGH}) — "
            "likely packed, encrypted, or obfuscated. "
            "Legitimate plaintext files score below 6.0.",
            location="raw_bytes",
            sample=f"entropy={entropy:.4f}",
        ))
    elif entropy >= _ENTROPY_MEDIUM:
        findings.append(_make_finding(
            "HEUR-001", "medium",
            f"File entropy is {entropy:.2f}/8.00 — elevated entropy, "
            "possible compression or partial obfuscation.",
            location="raw_bytes",
            sample=f"entropy={entropy:.4f}",
        ))

    return findings


def _check_non_printable(data: bytes, extension: str) -> list[ContentFinding]:
    """HEUR-002 — High non-printable byte ratio for text-expected files."""
    findings: list[ContentFinding] = []
    # Only warn for file types expected to be text/structured
    text_extensions = {".csv", ".txt", ".json", ".jsonl", ".xml", ".html", ".py", ".js"}
    if extension.lower() not in text_extensions:
        return findings

    ratio = _non_printable_ratio(data)
    if ratio > _NON_PRINTABLE_RATIO:
        findings.append(_make_finding(
            "HEUR-002", "high",
            f"{ratio * 100:.1f}% of bytes in this {extension} file are non-printable "
            "(expected <30%). Possible binary payload masquerading as text.",
            location="raw_bytes",
            sample=f"non_printable_ratio={ratio:.4f}",
        ))

    return findings


def _check_process_injection(data: bytes) -> list[ContentFinding]:
    """HEUR-003 — Process injection API strings."""
    findings: list[ContentFinding] = []
    matches = _PROCESS_INJECTION_BYTES.findall(data)
    if matches:
        unique = list({m.decode("ascii", errors="replace") for m in matches})[:5]
        findings.append(_make_finding(
            "HEUR-003", "high",
            f"Process injection API strings detected: {', '.join(unique)}. "
            "These are used by malware to inject code into other processes.",
            location="raw_bytes",
            sample=", ".join(unique)[:200],
        ))
    return findings


def _check_downloader_strings(data: bytes) -> list[ContentFinding]:
    """HEUR-004 — Script-based downloader / living-off-the-land strings."""
    findings: list[ContentFinding] = []
    matches = _DOWNLOADER_BYTES.findall(data)
    if matches:
        unique = list({m.decode("ascii", errors="replace") for m in matches})[:5]
        findings.append(_make_finding(
            "HEUR-004", "critical",
            f"Script-based downloader or LOLBIN string detected: {', '.join(unique)}. "
            "Common in malware dropper and downloader stages.",
            location="raw_bytes",
            sample=", ".join(unique)[:200],
        ))
    return findings


def _check_embedded_pe(data: bytes) -> list[ContentFinding]:
    """HEUR-005 — PE header (MZ+PE\x00\x00) found past offset 0 in non-PE file."""
    findings: list[ContentFinding] = []
    # Only flag if file does not start with MZ (that's already caught by MAL-002)
    if data[:2] == b"MZ":
        return findings  # handled by raw_bytes_scan MAL-002

    # Search for MZ followed by PE signature anywhere after offset 512
    idx = 512
    while idx < len(data) - 4:
        pos = data.find(b"MZ", idx)
        if pos == -1:
            break
        # Validate: check for PE\x00\x00 signature at offset stored in MZ header
        try:
            pe_offset = int.from_bytes(data[pos + 0x3C: pos + 0x40], "little")
            if 0 < pe_offset < 0x400 and (pos + pe_offset + 4) < len(data):
                if data[pos + pe_offset: pos + pe_offset + 4] == b"PE\x00\x00":
                    findings.append(_make_finding(
                        "HEUR-005", "critical",
                        f"Valid embedded PE executable found at byte offset {pos} "
                        "(polyglot / dropper file — PE header with valid signature).",
                        location=f"raw_bytes:offset={pos}",
                        sample=f"MZ+PE at offset {pos}",
                    ))
                    break
        except Exception:  # noqa: BLE001
            pass
        idx = pos + 1

    return findings


def _check_packer(data: bytes) -> list[ContentFinding]:
    """HEUR-006 — Known packer / protector section names."""
    findings: list[ContentFinding] = []
    matches = _PACKER_SECTIONS.findall(data)
    if matches:
        names = list({m.decode("ascii", errors="replace") for m in matches})
        findings.append(_make_finding(
            "HEUR-006", "high",
            f"Known packer/protector section name(s) found: {', '.join(names)}. "
            "Packed executables are frequently used to evade antivirus scanners.",
            location="raw_bytes",
            sample=", ".join(names)[:200],
        ))
    return findings


def _check_mime_mismatch(file_path: Path, data: bytes) -> list[ContentFinding]:
    """HEUR-007 — MIME type / file extension mismatch (requires python-magic)."""
    findings: list[ContentFinding] = []
    if not _HAS_MAGIC:
        return findings  # optional dependency not installed — skip gracefully

    try:
        detected_mime: str = _magic.from_buffer(data[:4096], mime=True)  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001
        return findings

    ext = file_path.suffix.lower()
    # Build expected MIME prefixes per extension
    _EXPECTED: dict[str, tuple[str, ...]] = {
        ".csv":     ("text/", "application/csv"),
        ".txt":     ("text/",),
        ".json":    ("text/", "application/json"),
        ".jsonl":   ("text/", "application/json"),
        ".xlsx":    ("application/vnd", "application/zip"),
        ".parquet": ("application/octet", "application/parquet"),
    }
    expected_prefixes = _EXPECTED.get(ext)
    if expected_prefixes and not any(detected_mime.startswith(p) for p in expected_prefixes):
        findings.append(_make_finding(
            "HEUR-007", "high",
            f"File extension '{ext}' does not match detected MIME type '{detected_mime}'. "
            "Malware commonly masquerades as benign file types.",
            location="file_header",
            sample=f"extension={ext}, detected_mime={detected_mime}",
        ))

    return findings


def _check_base64_payload(data: bytes) -> list[ContentFinding]:
    """HEUR-008 — Dense base64 block with high entropy (encoded payload)."""
    findings: list[ContentFinding] = []
    for match in _B64_BLOCK.finditer(data):
        block = match.group(0)
        try:
            block_entropy = calculate_entropy(block)
        except Exception:  # noqa: BLE001
            continue
        if block_entropy >= _B64_ENTROPY_THRESHOLD:
            preview = block[:60].decode("ascii", errors="replace")
            findings.append(_make_finding(
                "HEUR-008", "high",
                f"Dense base64-encoded block of {len(block)} bytes detected "
                f"(entropy={block_entropy:.2f}) — possible encoded payload or dropper stage.",
                location=f"raw_bytes:offset={match.start()}",
                sample=f"{preview}...",
            ))
            break  # one finding per file to avoid noise

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# Optional: pefile-based PE Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _check_pe_suspicious_imports(data: bytes) -> list[ContentFinding]:
    """Optional HEUR-003 enhancement: pefile-based import analysis."""
    if not _HAS_PEFILE or data[:2] != b"MZ":
        return []
    try:
        import io
        pe = _pefile.PE(data=data, fast_load=True)  # type: ignore[union-attr]
        pe.parse_data_directories(
            directories=[_pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]  # type: ignore[index]
        )
        suspicious_imports = {
            "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory",
            "NtUnmapViewOfSection", "SetWindowsHookEx", "QueueUserAPC",
        }
        found: list[str] = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    name = getattr(imp, "name", None)
                    if name and name.decode("ascii", errors="replace") in suspicious_imports:
                        found.append(name.decode("ascii", errors="replace"))
        if found:
            return [_make_finding(
                "HEUR-003", "high",
                f"PE import table contains process injection APIs: {', '.join(found[:6])}.",
                location="pe_imports",
                sample=", ".join(found[:6]),
            )]
    except Exception:  # noqa: BLE001
        pass
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def _compute_risk_score(findings: list[ContentFinding]) -> float:
    """
    Produce a 0.0–1.0 heuristic risk score from findings.
    Unlike content_checker (0–10 scale), this returns a 0–1 float
    for consistent integration with the engine's risk calculation.
    """
    _WEIGHTS = {"critical": 0.35, "high": 0.20, "medium": 0.10, "low": 0.03}
    total = sum(_WEIGHTS.get(f.severity, 0.0) for f in findings)
    return round(min(total, 1.0), 4)


def heuristic_scan(file_path: str) -> tuple[list[ContentFinding], float]:
    """
    Stage 0.5 — Signature-less heuristic analysis.

    Reads up to 1 MB of the file and runs 8 heuristic checks.
    Returns (findings, risk_score_0_to_1).

    If heuristics are disabled via ENABLE_HEURISTICS=false in the environment,
    returns ([], 0.0) immediately.
    """
    import os
    if os.getenv("ENABLE_HEURISTICS", "true").lower() in ("false", "0", "no"):
        return [], 0.0

    path = Path(file_path)
    findings: list[ContentFinding] = []

    try:
        file_size = path.stat().st_size
    except OSError as exc:
        logger.warning("heuristic_scan: cannot stat %s — %s", file_path, exc)
        return [], 0.0

    if file_size < _MIN_BYTES:
        logger.debug("heuristic_scan: skipping tiny file %s (%d bytes)", path.name, file_size)
        return [], 0.0

    try:
        with path.open("rb") as fh:
            data = fh.read(_MAX_BYTES)
    except OSError as exc:
        logger.warning("heuristic_scan: cannot read %s — %s", file_path, exc)
        return [], 0.0

    ext = path.suffix.lower()

    # Run all heuristics — each returns a (possibly empty) list of findings
    checks = [
        _check_entropy(data, file_size),
        _check_non_printable(data, ext),
        _check_process_injection(data),
        _check_downloader_strings(data),
        _check_embedded_pe(data),
        _check_packer(data),
        _check_mime_mismatch(path, data),
        _check_base64_payload(data),
        _check_pe_suspicious_imports(data),
    ]
    for check_findings in checks:
        findings.extend(check_findings)

    score = _compute_risk_score(findings)
    logger.info(
        "heuristic_scan: %s — %d finding(s), risk_score=%.4f",
        path.name, len(findings), score,
    )
    return findings, score
