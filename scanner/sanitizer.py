"""
Aegis Node — Dataset Sanitizer & Remediation Engine.
Applies format-aware, deterministic, non-destructive threat remediation to CSV & JSON datasets.

Security Principles Enforced:
  1. Original Immutability: The original file is never overwritten.
  2. Format-Aware Parsing: Operates on parsed pandas/json data structures in memory.
  3. No Execution Guarantee: Zero eval(), exec(), or SQL evaluation.
  4. Formula Neutralization: Spreadsheet trigger chars (=, +, -, @, |, DDE) are prefixed with a single quote (').
  5. Script Tag & Payload Neutralization: Dangerous executable markup is converted to inert text.
  6. Severity-Based SQL Redaction: HIGH/CRITICAL SQL threats replace the ENTIRE field value with [REMOVED].
  7. Auditable Transformations: Every change is logged with rule_id, category, location, and action taken.
"""

import io
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)

# Maximum rows sanitized per dataset
_MAX_ROWS = 10_000


@dataclass
class RemediationAction:
    rule_id: str
    category: str
    location: str
    action_taken: str
    sample_after: str = ""


@dataclass
class SanitizerResult:
    sanitized_bytes: bytes = b""
    changes_count: int = 0
    actions: list[RemediationAction] = field(default_factory=list)
    error: str | None = None


# ─── Transformation functions per category ───────────────────────────────────

def _remediate_formula_cell(val: str) -> tuple[str, bool, str]:
    """
    Neutralize CSV Formula Injection.
    Prepend a single quote (') if val starts with =, +, -, @, |, DDE, cmd|, powershell|.
    Returns (new_val, changed, rule_id).
    """
    # Check DDE/cmd patterns first
    if re.search(r'DDE\s*\(|cmd\s*\||powershell\s*\|', val, re.IGNORECASE):
        new_val = "'" + val
        return new_val, True, "FORM-002"

    if re.search(r'HYPERLINK\s*\(', val, re.IGNORECASE):
        new_val = "'" + val
        return new_val, True, "FORM-003"

    # Standard formula trigger character check
    if re.match(r'^\s*[=+\-@|]', val):
        new_val = "'" + val
        return new_val, True, "FORM-001"

    return val, False, ""


def _remediate_script_cell(val: str) -> tuple[str, bool, str]:
    """
    Neutralize Script / HTML Injection.
    Converts <script> to [script_removed], javascript: to [js_removed]:, eval()/exec() to [eval_removed].
    """
    changed = False
    rule_id = ""
    new_val = val

    if re.search(r'<\s*script[\s>]', new_val, re.IGNORECASE):
        new_val = re.sub(r'<\s*script[^>]*>', '[script_removed]', new_val, flags=re.IGNORECASE)
        new_val = re.sub(r'</\s*script\s*>', '[/script_removed]', new_val, flags=re.IGNORECASE)
        changed = True
        rule_id = "SCRP-001"

    if re.search(r'javascript\s*:', new_val, re.IGNORECASE):
        new_val = re.sub(r'javascript\s*:', '[js_removed]:', new_val, flags=re.IGNORECASE)
        changed = True
        if not rule_id:
            rule_id = "SCRP-002"

    if re.search(r'\beval\s*\(|\bexec\s*\(', new_val, re.IGNORECASE):
        new_val = re.sub(r'\beval\s*\(', '[eval_removed](', new_val, flags=re.IGNORECASE)
        new_val = re.sub(r'\bexec\s*\(', '[exec_removed](', new_val, flags=re.IGNORECASE)
        changed = True
        if not rule_id:
            rule_id = "SCRP-003"

    return new_val, changed, rule_id


# SQL injection severity thresholds:
# HIGH/CRITICAL: the field is completely wiped to [REMOVED] (zero residual risk)
# MEDIUM/LOW:    keywords are redacted inline
_SQL_HIGH_SEVERITY_RULES = {"SQLI-001", "SQLI-002"}  # both are high-severity by design


def _remediate_sql_cell(
    val: str,
    force_full_remove: bool = False,
) -> tuple[str, bool, str]:
    """
    Neutralize SQL-like injection strings in text fields without SQL execution.
    If force_full_remove=True (HIGH/CRITICAL severity), the entire field value is replaced with [REMOVED].
    """
    changed = False
    rule_id = ""
    new_val = val

    has_or_injection = bool(re.search(r"'\s*OR\s*'1'\s*=\s*'1|--\s|;\s*DROP\s+TABLE", new_val, re.IGNORECASE))
    has_union = bool(re.search(r"UNION\s+(ALL\s+)?SELECT", new_val, re.IGNORECASE))

    if has_or_injection:
        rule_id = "SQLI-001"
        changed = True
    if has_union:
        if not rule_id:
            rule_id = "SQLI-002"
        changed = True

    if not changed:
        return new_val, False, ""

    if force_full_remove or rule_id in _SQL_HIGH_SEVERITY_RULES:
        # Complete field removal for HIGH/CRITICAL severity — zero remnant risk
        return "[REMOVED]", True, rule_id

    # Medium/LOW severity: inline keyword redaction only
    if has_or_injection:
        new_val = re.sub(r"'\s*OR\s*'1'\s*=\s*'1", "[sql_payload_neutralized]", new_val, flags=re.IGNORECASE)
        new_val = re.sub(r";\s*DROP\s+TABLE", "; [drop_table_neutralized]", new_val, flags=re.IGNORECASE)
    if has_union:
        new_val = re.sub(r"UNION\s+(ALL\s+)?SELECT", "[union_select_neutralized]", new_val, flags=re.IGNORECASE)
    return new_val, True, rule_id


# Malware signature patterns for cell-level neutralization (EICAR, malware tools, etc.)
_EICAR_STR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
_MALWARE_PATTERNS = [
    (re.compile(re.escape(_EICAR_STR) + r"|EICAR-STANDARD-ANTIVIRUS-TEST-FILE", re.IGNORECASE), "MAL-001"),
    (re.compile(r"\b(mimikatz|sekurlsa|kerberos::|lsadump)\b", re.IGNORECASE), "MAL-004"),
    (re.compile(r"\b(cobalt\s*strike|beacon\.dll|beacon\.exe)\b", re.IGNORECASE), "MAL-005"),
    (re.compile(r"\b(metasploit|meterpreter|reverse_tcp)\b", re.IGNORECASE), "MAL-006"),
    (re.compile(r"\b(wannacry|wcry|wncry)\b", re.IGNORECASE), "MAL-007"),
    (re.compile(r"\b(lockbit|revil|sodinokibi)\b", re.IGNORECASE), "MAL-008"),
    (re.compile(r"\b(Invoke-Mimikatz|Invoke-ReflectivePEInjection)\b", re.IGNORECASE), "MAL-009"),
]


def _remediate_malware_cell(val: str) -> tuple[str, bool, str]:
    """
    Neutralize malware signatures/strings (EICAR, malware tool names, etc.)
    For critical/high malware signatures, replaces the ENTIRE field with [REMOVED].
    """
    for pattern, rule_id in _MALWARE_PATTERNS:
        if pattern.search(val):
            return "[REMOVED]", True, rule_id
    return val, False, ""


def _remediate_binary_cell(val: str) -> tuple[str, bool, str]:
    """Strip null bytes (\\x00) from string fields."""
    if '\x00' in val:
        new_val = val.replace('\x00', '')
        return new_val, True, "BIN-001"
    return val, False, ""


def _format_sample_after(val: str, is_redacted: bool = False) -> str:
    """Format sample_after with max 50 chars and redaction support (A-012)."""
    if is_redacted or val == "[REMOVED]":
        return "[REMOVED]"
    return val[:50]


def _sanitize_cell_value(val: str, col_name: str, row_idx: str) -> tuple[str, list[RemediationAction]]:
    """Apply all category transformations sequentially to a single cell string."""
    actions = []
    current = val

    # 0. Malware signatures & EICAR test string removal (CRITICAL -> full field removal)
    current, c0, r0 = _remediate_malware_cell(current)
    if c0:
        actions.append(RemediationAction(
            rule_id=r0, category="malware_signature", location=f"col='{col_name}', row={row_idx}",
            action_taken="Completely removed malware signature from field (severity=critical)",
            sample_after="[REMOVED]",
        ))
        return current, actions

    # 1. Null byte removal
    current, c1, r1 = _remediate_binary_cell(current)
    if c1:
        actions.append(RemediationAction(
            rule_id=r1, category="binary_anomaly", location=f"col='{col_name}', row={row_idx}",
            action_taken="Stripped null byte (\\x00) control characters",
            sample_after=_format_sample_after(current),
        ))

    # 2. Formula injection neutralization
    current, c2, r2 = _remediate_formula_cell(current)
    if c2:
        actions.append(RemediationAction(
            rule_id=r2, category="formula_injection", location=f"col='{col_name}', row={row_idx}",
            action_taken="Prefixed formula trigger with single quote (') to prevent execution",
            sample_after=_format_sample_after(current),
        ))

    # 3. Script / HTML injection neutralization
    current, c3, r3 = _remediate_script_cell(current)
    if c3:
        actions.append(RemediationAction(
            rule_id=r3, category="script_injection", location=f"col='{col_name}', row={row_idx}",
            action_taken="Replaced executable script markup with inert text tag",
            sample_after=_format_sample_after(current),
        ))

    # 4. SQL injection string neutralization (HIGH/CRITICAL → full field removal)
    # Since both SQLI rules are treated as high-severity, use full removal by default
    current, c4, r4 = _remediate_sql_cell(current, force_full_remove=True)
    if c4:
        action_desc = (
            "Completely removed field value (severity=high — zero residual SQL payload risk)"
            if current == "[REMOVED]"
            else "Neutralized SQL injection payload string"
        )
        actions.append(RemediationAction(
            rule_id=r4, category="sql_injection", location=f"col='{col_name}', row={row_idx}",
            action_taken=action_desc,
            sample_after=_format_sample_after(current, is_redacted=(current == "[REMOVED]")),
        ))

    return current, actions


def sanitize_dataframe(df: pd.DataFrame) -> tuple[pd.DataFrame, int, list[RemediationAction]]:
    """Sanitize all string columns in a DataFrame."""
    df_clean = df.copy()
    total_changes = 0
    all_actions = []

    for col in df_clean.columns:
        col_name = str(col)
        # Process non-null string series
        col_series = df_clean[col].dropna().astype(str)

        for row_idx, val in col_series.items():
            new_val, actions = _sanitize_cell_value(val, col_name, str(row_idx))
            if actions:
                df_clean.at[row_idx, col] = new_val
                total_changes += len(actions)
                all_actions.extend(actions)

    return df_clean, total_changes, all_actions


def sanitize_file(file_path: str, file_format: str) -> SanitizerResult:
    """
    Main entry point: Read file, sanitize string columns, export sanitized bytes.
    Supports CSV and JSON formats.
    Does NOT overwrite original file.
    """
    path = Path(file_path)
    result = SanitizerResult()

    if not path.exists():
        result.error = f"Original file not found: {file_path}"
        return result

    fmt = file_format.lower()
    ext = path.suffix.lower()

    try:
        if fmt == "csv" or ext == ".csv":
            df = pd.read_csv(path, nrows=_MAX_ROWS, low_memory=False, dtype=str)
            df_clean, total_changes, actions = sanitize_dataframe(df)

            out_buffer = io.StringIO()
            df_clean.to_csv(out_buffer, index=False)
            result.sanitized_bytes = out_buffer.getvalue().encode("utf-8")
            result.changes_count = total_changes
            result.actions = actions

        elif fmt in ("json", "jsonl") or ext in (".json", ".jsonl"):
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                raw_data = json.load(fh)

            if isinstance(raw_data, list):
                df = pd.DataFrame(raw_data[:_MAX_ROWS]).astype(str)
                df_clean, total_changes, actions = sanitize_dataframe(df)
                records = df_clean.to_dict(orient="records")
                result.sanitized_bytes = json.dumps(records, indent=2).encode("utf-8")
            elif isinstance(raw_data, dict):
                df = pd.DataFrame([raw_data]).astype(str)
                df_clean, total_changes, actions = sanitize_dataframe(df)
                rec = df_clean.to_dict(orient="records")[0]
                result.sanitized_bytes = json.dumps(rec, indent=2).encode("utf-8")
            else:
                result.error = f"Unsupported JSON structure: {type(raw_data).__name__}"
                return result

            result.changes_count = total_changes
            result.actions = actions

        elif fmt == "parquet" or ext == ".parquet":
            df = pd.read_parquet(path)
            df = df.head(_MAX_ROWS).astype(str)
            df_clean, total_changes, actions = sanitize_dataframe(df)

            out_buffer = io.BytesIO()
            df_clean.to_parquet(out_buffer, index=False)
            result.sanitized_bytes = out_buffer.getvalue()
            result.changes_count = total_changes
            result.actions = actions

        elif fmt == "xlsx" or ext == ".xlsx":
            df = pd.read_excel(path, nrows=_MAX_ROWS, dtype=str)
            df_clean, total_changes, actions = sanitize_dataframe(df)

            out_buffer = io.BytesIO()
            df_clean.to_excel(out_buffer, index=False)
            result.sanitized_bytes = out_buffer.getvalue()
            result.changes_count = total_changes
            result.actions = actions

        elif fmt == "txt" or ext == ".txt":
            with path.open("r", encoding="utf-8", errors="replace") as fh:
                lines = [line.rstrip("\r\n") for line in fh]

            sanitized_lines = []
            total_changes = 0
            actions = []
            for idx, line in enumerate(lines[:_MAX_ROWS]):
                clean_line, line_actions = _sanitize_cell_value(line, "line", str(idx + 1))
                sanitized_lines.append(clean_line)
                if line_actions:
                    total_changes += len(line_actions)
                    actions.extend(line_actions)

            result.sanitized_bytes = "\n".join(sanitized_lines).encode("utf-8")
            result.changes_count = total_changes
            result.actions = actions

        else:
            result.error = f"Unsupported file format for remediation: {file_format!r}"

    except Exception as exc:  # noqa: BLE001
        logger.error("Sanitization error for %s: %s", file_path, exc)
        result.error = f"Failed to sanitize file: {exc}"

    return result
