"""
Aegis Node — YARA Pattern Matching Scanner.
Executes compiled YARA rules against raw file streams and individual dataset cells.

Architecture:
- Compiles rules from `backend/rules/yara/*.yar` at startup.
- Provides `scan_file`, `scan_text`, and `scan_bytes` interfaces.
- Gracefully handles missing YARA C-extensions or compilation errors without failing the scan pipeline.
"""

import logging
from pathlib import Path
from schemas import ThreatFinding

logger = logging.getLogger(__name__)

# Try importing yara safely
try:
    import yara
    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False
    logger.warning("yara-python package not installed — YARA scanning will run in unavailable/mock mode")


class YaraScanner:
    """YARA scanning engine for Aegis Node."""

    def __init__(self, rules_dir: Path | str | None = None):
        self.rules = None
        self.is_available = _YARA_AVAILABLE
        self.rules_loaded = 0

        if rules_dir is None:
            # Default to backend/rules/yara/
            curr = Path(__file__).resolve().parent
            root = curr.parent.parent if curr.parent.name == "backend" else curr.parent
            rules_dir = root / "backend" / "rules" / "yara"
            if not rules_dir.exists():
                rules_dir = root / "rules" / "yara"

        self.rules_dir = Path(rules_dir)
        if self.is_available:
            self._compile_rules()

    def _compile_rules(self) -> None:
        """Compile all .yar files in the rules directory."""
        if not self.rules_dir.exists():
            logger.warning("YARA rules directory does not exist: %s", self.rules_dir)
            return

        yar_files = list(self.rules_dir.glob("*.yar"))
        if not yar_files:
            logger.warning("No .yar rule files found in %s", self.rules_dir)
            return

        filepaths = {f"rule_{idx}": str(p) for idx, p in enumerate(yar_files)}
        try:
            self.rules = yara.compile(filepaths=filepaths)
            self.rules_loaded = len(yar_files)
            logger.info("Compiled %d YARA rule files from %s", self.rules_loaded, self.rules_dir)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to compile YARA rules: %s", exc)
            self.rules = None

    def scan_bytes(self, data: bytes, location: str = "raw") -> list[ThreatFinding]:
        """Scan a byte string and return matched ThreatFinding instances."""
        if not self.is_available or not self.rules or not data:
            return []

        findings: list[ThreatFinding] = []
        try:
            matches = self.rules.match(data=data)
            for match in matches:
                meta = match.meta or {}
                rule_id = meta.get("rule_id", f"YARA-{match.rule.upper()}")
                severity = meta.get("severity", "HIGH").lower()
                category = meta.get("category", "malware_artifact")
                desc = meta.get("description", f"YARA matched rule {match.rule}")

                # Extract matched string snippet safely
                sample_snippet = ""
                if match.strings:
                    try:
                        raw_match = match.strings[0]
                        # In yara-python, match.strings tuples are (offset, identifier, data)
                        matched_bytes = raw_match[2] if len(raw_match) > 2 else b""
                        sample_snippet = matched_bytes[:100].decode("utf-8", errors="replace")
                    except Exception:
                        sample_snippet = match.rule

                findings.append(
                    ThreatFinding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        description=desc,
                        location=location,
                        sample=sample_snippet or match.rule,
                    )
                )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error during YARA byte scan: %s", exc)

        return findings

    def scan_text(self, text: str, location: str = "cell") -> list[ThreatFinding]:
        """Scan a text string and return matched ThreatFinding instances."""
        if not text or not text.strip():
            return []
        data = text.encode("utf-8", errors="ignore")
        return self.scan_bytes(data, location=location)

    def scan_file(self, path: Path | str) -> list[ThreatFinding]:
        """Scan a file on disk using YARA."""
        p = Path(path)
        if not p.exists() or not self.is_available or not self.rules:
            return []

        try:
            with open(p, "rb") as f:
                data = f.read(2 * 1024 * 1024)  # Scan first 2MB for executable headers
            return self.scan_bytes(data, location="file_header")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Error reading file for YARA scan: %s", exc)
            return []


# Global singleton instance
yara_scanner = YaraScanner()
