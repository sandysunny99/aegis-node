"""
Static SkillSpector scan of the agent skills and instructions Aegis Node is built with.

This is a development / CI tool. It never touches the dataset scanner, and its
results never feed a dataset verdict. See docs/security/SKILL_SECURITY_SCANNING.md.

What it does, per approved target in security/skill_scan_targets.json:
  1. checks the target path is relative, inside the repo, not a symlink, within the
     file-count and size caps, and does not contain the policy or triage file;
  2. checks the scanner reports the pinned SkillSpector version;
  3. runs `skillspector scan <target> --no-llm --format json` as an argument list,
     with a time budget, a minimal environment (no provider keys) and outbound
     HTTP(S) pointed at a dead local proxy;
  4. validates and size-bounds the JSON report, treating it as untrusted data;
  5. writes a sanitized summary (rule ids, files, lines and keys only; no code
     snippets, matched text or absolute paths) and applies the reviewed triage file.

Exit codes: 0 = passed, or --mode report; 1 = gate failed; 2 = bad policy, triage
or arguments (nothing is scanned).

Usage (from the repo root):
    python scripts/skill_scan.py --scanner /path/to/venv/bin/skillspector --mode report
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPO_ROOT / "security" / "skill_scan_targets.json"
DEFAULT_TRIAGE = REPO_ROOT / "security" / "skill_scan_triage.json"
DEFAULT_OUT = REPO_ROOT / "reports" / "security"

SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}
RECOMMENDATIONS = {"SAFE", "CAUTION", "DO_NOT_INSTALL"}
TARGET_KINDS = {"claude_skill", "agent_rules", "agent_guidance", "mcp_config",
                "agent_script", "ci_workflow"}
TRIAGE_CLASSES = {"confirmed_risk", "likely_risk", "false_positive", "accepted_risk",
                  "incomplete_analysis"}
SUPPRESSING_CLASSES = {"false_positive", "accepted_risk"}
SHIPPED_BASELINES = {".skillspector-baseline.yaml", ".skillspector-baseline.yml",
                     ".skillspector-baseline.json"}
# Unroutable local proxy: SkillSpector's SC4 check would otherwise send dependency
# names to api.osv.dev even with --no-llm. With this it uses its built-in list.
DEAD_PROXY = "http://127.0.0.1:9"
MAX_ISSUES = 2000

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
_KEY_RE = re.compile(r"^[0-9a-f]{16}$")
_RULE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"SkillSpector v(\S+)")


class PolicyError(Exception):
    """The policy, triage file or arguments are unusable; nothing is scanned."""


class ReportError(Exception):
    """The scanner's report is malformed, oversized or out of contract."""


# ---------------------------------------------------------------------------
# Policy and triage
# ---------------------------------------------------------------------------

def _load_json(path: Path, what: str):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"cannot read {what} {path.name}: {exc}") from exc


def _positive_int(limits: dict, name: str) -> int:
    value = limits.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise PolicyError(f"limits.{name} must be a positive integer")
    return value


def _text(entry: dict, name: str, where: str, min_len: int = 1) -> str:
    value = entry.get(name)
    if not isinstance(value, str) or len(value.strip()) < min_len:
        raise PolicyError(f"{where}: '{name}' must be text of at least {min_len} characters")
    return value


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _resolve_target(repo_root: Path, rel: str, where: str) -> Path:
    if not rel or "\\" in rel or rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
        raise PolicyError(f"{where}: path must be a non-empty relative POSIX path")
    parts = PurePosixPath(rel).parts
    if not parts or any(p in ("..", ".") for p in parts):
        raise PolicyError(f"{where}: path may not contain '.' or '..' segments")
    current = repo_root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise PolicyError(f"{where}: {rel} goes through a symlink")
    if not current.exists():
        raise PolicyError(f"{where}: {rel} does not exist")
    if not _is_within(current.resolve(), repo_root):
        raise PolicyError(f"{where}: {rel} resolves outside the repository")
    return current


def _check_contents(path: Path, rel: str, where: str, limits: dict) -> int:
    files = [path] if path.is_file() else sorted(path.rglob("*"))
    count = 0
    for item in files:
        if item.is_symlink():
            raise PolicyError(f"{where}: {rel} contains a symlink")
        if item.name in SHIPPED_BASELINES:
            raise PolicyError(f"{where}: {rel} ships its own SkillSpector baseline; "
                              "a target may not supply its own suppressions")
        if not item.is_file():
            continue
        count += 1
        if count > limits["max_files_per_target"]:
            raise PolicyError(f"{where}: {rel} has more than "
                              f"{limits['max_files_per_target']} files")
        if item.stat().st_size > limits["max_file_bytes"]:
            raise PolicyError(f"{where}: a file in {rel} is larger than "
                              f"{limits['max_file_bytes']} bytes")
    return count


def load_policy(policy_path: Path, triage_path: Path, repo_root: Path) -> dict:
    repo_root = repo_root.resolve()
    raw = _load_json(policy_path, "policy")
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise PolicyError("policy: expected an object with version 1")
    tool = raw.get("skillspector")
    if not isinstance(tool, dict):
        raise PolicyError("policy: 'skillspector' must name the pinned version and commit")
    version = _text(tool, "version", "policy.skillspector")
    commit = _text(tool, "commit", "policy.skillspector")
    if not _SHA_RE.match(commit):
        raise PolicyError("policy.skillspector.commit must be a full 40-character SHA")
    limits_raw = raw.get("limits")
    if not isinstance(limits_raw, dict):
        raise PolicyError("policy: 'limits' is required")
    limits = {name: _positive_int(limits_raw, name) for name in
              ("timeout_seconds", "max_files_per_target", "max_file_bytes",
               "max_report_bytes")}

    protected = [policy_path.resolve(), triage_path.resolve()]
    targets_raw = raw.get("targets")
    if not isinstance(targets_raw, list) or not targets_raw:
        raise PolicyError("policy: 'targets' must be a non-empty list")
    targets, seen = [], set()
    for index, entry in enumerate(targets_raw):
        where = f"policy.targets[{index}]"
        if not isinstance(entry, dict):
            raise PolicyError(f"{where}: must be an object")
        target_id = _text(entry, "id", where)
        if not _ID_RE.match(target_id) or target_id in seen:
            raise PolicyError(f"{where}: id must be unique, lowercase, [a-z0-9_-]")
        seen.add(target_id)
        kind = _text(entry, "kind", where)
        if kind not in TARGET_KINDS:
            raise PolicyError(f"{where}: kind must be one of {sorted(TARGET_KINDS)}")
        reason = _text(entry, "reason", where)
        rel = entry.get("path")
        if not isinstance(rel, str):
            raise PolicyError(f"{where}: path must be text")
        path = _resolve_target(repo_root, rel, where)
        for item in protected:
            if _is_within(item, path.resolve()):
                raise PolicyError(f"{where}: {rel} contains the policy or triage file")
        files = _check_contents(path, rel, where, limits)
        targets.append({"id": target_id, "path": rel, "abs": path, "kind": kind,
                        "reason": reason, "files": files})

    exclusions = raw.get("exclusions", [])
    if not isinstance(exclusions, list):
        raise PolicyError("policy: 'exclusions' must be a list")
    for index, entry in enumerate(exclusions):
        where = f"policy.exclusions[{index}]"
        if not isinstance(entry, dict):
            raise PolicyError(f"{where}: must be an object")
        _text(entry, "path", where)
        _text(entry, "reason", where)
    return {"version": version, "commit": commit, "limits": limits, "targets": targets,
            "exclusions": [{"path": e["path"], "reason": e["reason"]} for e in exclusions]}


def load_triage(triage_path: Path, policy: dict) -> dict:
    raw = _load_json(triage_path, "triage file")
    if not isinstance(raw, dict) or raw.get("version") != 1 or not isinstance(
            raw.get("entries"), list):
        raise PolicyError("triage: expected an object with version 1 and an 'entries' list")
    target_ids = {t["id"] for t in policy["targets"]}
    entries = {}
    for index, entry in enumerate(raw["entries"]):
        where = f"triage.entries[{index}]"
        if not isinstance(entry, dict):
            raise PolicyError(f"{where}: must be an object")
        key = _text(entry, "key", where)
        if not _KEY_RE.match(key) or key in entries:
            raise PolicyError(f"{where}: key must be a unique 16-character hex finding key")
        if _text(entry, "target", where) not in target_ids:
            raise PolicyError(f"{where}: target is not in the policy")
        if _text(entry, "classification", where) not in TRIAGE_CLASSES:
            raise PolicyError(f"{where}: classification must be one of "
                              f"{sorted(TRIAGE_CLASSES)}")
        _text(entry, "rule_id", where)
        _text(entry, "file", where)
        _text(entry, "owner", where)
        _text(entry, "reason", where, min_len=15)
        if not _DATE_RE.match(_text(entry, "reviewed", where)):
            raise PolicyError(f"{where}: reviewed must be YYYY-MM-DD")
        occurrences = entry.get("occurrences")
        if not isinstance(occurrences, int) or isinstance(occurrences, bool) or occurrences < 1:
            raise PolicyError(f"{where}: occurrences must be the positive number of matches "
                              "that were reviewed")
        entries[key] = entry
    return entries


# ---------------------------------------------------------------------------
# Running the scanner
# ---------------------------------------------------------------------------

def scanner_command(scanner: Path) -> list[str]:
    if not scanner.is_file():
        raise PolicyError(f"scanner not found: {scanner}")
    if scanner.suffix == ".py":
        return [sys.executable, "-I", str(scanner)]
    return [str(scanner)]


def scanner_env(home: str) -> dict:
    """A minimal environment: no provider keys, no tokens, outbound HTTP(S) blocked."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": home, "USERPROFILE": home, "TMPDIR": home, "TEMP": home, "TMP": home,
        "LANG": "C.UTF-8", "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
        "NO_COLOR": "1", "SKILLSPECTOR_LOG_LEVEL": "ERROR",
        "HTTP_PROXY": DEAD_PROXY, "HTTPS_PROXY": DEAD_PROXY, "ALL_PROXY": DEAD_PROXY,
        "http_proxy": DEAD_PROXY, "https_proxy": DEAD_PROXY, "all_proxy": DEAD_PROXY,
        "NO_PROXY": "", "no_proxy": "",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT"):
        if name in os.environ:
            env[name] = os.environ[name]
    return env


def _probe_version(command: list[str], env: dict, cwd: str, timeout: int) -> str:
    result = subprocess.run([*command, "--version"], stdin=subprocess.DEVNULL,
                            capture_output=True, text=True, timeout=timeout, env=env,
                            cwd=cwd, check=False)
    match = _VERSION_RE.search(result.stdout[:500])
    return match.group(1) if match else ""


def run_scanner(target: dict, policy: dict, command: list[str]) -> dict:
    """Run one static scan. Returns status, exit code, timing and the raw report bytes."""
    limits = policy["limits"]
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="aegis_skillscan_") as work:
        env = scanner_env(work)
        try:
            found = _probe_version(command, env, work, min(60, limits["timeout_seconds"]))
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "tool_error", "detail": f"version check failed: {type(exc).__name__}"}
        if found != policy["version"]:
            return {"status": "tool_error",
                    "detail": f"scanner version {found or 'unknown'} is not the pinned "
                              f"{policy['version']}"}
        out_path = Path(work) / "report.json"
        args = [*command, "scan", str(target["abs"]), "--no-llm", "--format", "json"]
        try:
            with open(out_path, "wb") as out, open(os.devnull, "wb") as err:
                proc = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                                      timeout=limits["timeout_seconds"], env=env, cwd=work,
                                      check=False)
        except subprocess.TimeoutExpired:
            return {"status": "tool_error",
                    "detail": f"timed out after {limits['timeout_seconds']}s",
                    "duration_seconds": round(time.monotonic() - started, 2)}
        except OSError as exc:
            return {"status": "tool_error", "detail": f"could not start scanner: {exc.strerror}"}
        size = out_path.stat().st_size
        raw = b""
        if size <= limits["max_report_bytes"]:
            raw = out_path.read_bytes()
        return {"status": "ran", "exit_code": proc.returncode, "report_bytes": size,
                "raw": raw, "oversized": size > limits["max_report_bytes"],
                "duration_seconds": round(time.monotonic() - started, 2)}


# ---------------------------------------------------------------------------
# Report validation and sanitizing
# ---------------------------------------------------------------------------

def _need(obj, key, kind, where):
    value = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(value, kind) or (kind is int and isinstance(value, bool)):
        raise ReportError(f"{where}.{key} missing or not {getattr(kind, '__name__', kind)}")
    return value


def _safe_path(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._/ -]", "?", value)[:200]
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", value):
        cleaned = PurePosixPath(cleaned).name
    return cleaned


def parse_report(raw: bytes, policy: dict) -> dict:
    """Validate a SkillSpector JSON report. Raises ReportError when out of contract."""
    try:
        report = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ReportError("report is not UTF-8 JSON") from exc
    if not isinstance(report, dict):
        raise ReportError("report is not a JSON object")
    risk = _need(report, "risk_assessment", dict, "report")
    score = _need(risk, "score", int, "risk_assessment")
    severity = _need(risk, "severity", str, "risk_assessment")
    recommendation = _need(risk, "recommendation", str, "risk_assessment")
    if not 0 <= score <= 100 or severity not in SEVERITIES or recommendation not in \
            RECOMMENDATIONS:
        raise ReportError("risk_assessment values out of range")
    meta = _need(report, "metadata", dict, "report")
    if _need(meta, "llm_requested", bool, "metadata"):
        raise ReportError("report says LLM analysis was requested; only static scans allowed")
    if _need(meta, "skillspector_version", str, "metadata") != policy["version"]:
        raise ReportError("report version is not the pinned version")
    completeness = _need(report, "analysis_completeness", dict, "report")
    status = _need(completeness, "status", str, "analysis_completeness")
    is_complete = _need(completeness, "is_complete", bool, "analysis_completeness")
    executed = report.get("execution_successful", completeness.get("execution_successful"))
    if not isinstance(executed, bool):
        raise ReportError("execution_successful missing")
    coverage = completeness.get("coverage_percent")
    if coverage is not None and not isinstance(coverage, int | float):
        raise ReportError("coverage_percent is not a number")
    reasons = sorted({re.sub(r"[^a-z0-9_]", "", str(e.get("reason_code", "")))[:64]
                      for e in completeness.get("ledger_exceptions", []) or []
                      if isinstance(e, dict)} - {""})
    components = report.get("components", [])
    if not isinstance(components, list):
        raise ReportError("components is not a list")
    issues = _need(report, "issues", list, "report")
    if len(issues) > MAX_ISSUES:
        raise ReportError(f"more than {MAX_ISSUES} issues")
    parsed = []
    for index, issue in enumerate(issues):
        where = f"issues[{index}]"
        rule_id = _need(issue, "id", str, where)
        sev = _need(issue, "severity", str, where)
        location = _need(issue, "location", dict, where)
        file = _need(location, "file", str, f"{where}.location")
        line = location.get("start_line")
        if not _RULE_RE.match(rule_id) or sev not in SEVERITIES:
            raise ReportError(f"{where}: unknown rule id or severity")
        if line is not None and (not isinstance(line, int) or isinstance(line, bool)):
            raise ReportError(f"{where}: start_line is not an integer")
        matched = issue.get("finding")
        category = issue.get("category")
        parsed.append({
            "rule_id": rule_id, "severity": sev, "file": _safe_path(file), "line": line,
            "category": re.sub(r"[^A-Za-z -]", "", category)[:48]
            if isinstance(category, str) else "",
            "_matched": matched if isinstance(matched, str) else "",
        })
    return {"score": score, "severity": severity, "recommendation": recommendation,
            "completeness_status": re.sub(r"[^a-z_]", "", status)[:32],
            "is_complete": is_complete, "execution_successful": executed,
            "coverage_percent": coverage, "ledger_reasons": reasons,
            "components": len(components), "issues": parsed}


def finding_key(target_id: str, rule_id: str, file: str, matched: str) -> str:
    """Stable key for triage. Ignores line numbers so edits above a finding keep its key."""
    blob = "\0".join((target_id, rule_id, file, matched)).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


def group_findings(target_id: str, issues: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for issue in issues:
        key = finding_key(target_id, issue["rule_id"], issue["file"], issue["_matched"])
        entry = grouped.setdefault(key, {
            "key": key, "rule_id": issue["rule_id"], "category": issue["category"],
            "severity": issue["severity"], "file": issue["file"], "lines": [],
            "occurrences": 0, "triage": None})
        entry["occurrences"] += 1
        if issue["line"] is not None and issue["line"] not in entry["lines"]:
            entry["lines"].append(issue["line"])
        if SEVERITIES.index(issue["severity"]) > SEVERITIES.index(entry["severity"]):
            entry["severity"] = issue["severity"]
    return sorted(grouped.values(), key=lambda f: (-SEVERITIES.index(f["severity"]),
                                                   f["file"], f["rule_id"], f["key"]))


def scan_target(target: dict, policy: dict, command: list[str]) -> dict:
    result = {"id": target["id"], "path": target["path"], "kind": target["kind"],
              "files": target["files"], "status": "tool_error", "detail": "",
              "findings": []}
    run = run_scanner(target, policy, command)
    for name in ("exit_code", "report_bytes", "duration_seconds"):
        if name in run:
            result[name] = run[name]
    if run["status"] != "ran":
        result["detail"] = run["detail"]
        return result
    if run["oversized"]:
        result.update(status="invalid_report",
                      detail=f"report larger than {policy['limits']['max_report_bytes']} bytes")
        return result
    if not run["raw"].strip():
        result["detail"] = f"no report (exit code {run['exit_code']})"
        return result
    try:
        report = parse_report(run["raw"], policy)
    except ReportError as exc:
        result.update(status="invalid_report", detail=str(exc))
        return result
    issues = report.pop("issues")
    result.update(report)
    result["findings"] = group_findings(target["id"], issues)
    if run["exit_code"] not in (0, 1):
        result.update(status="tool_error", detail=f"scanner exit code {run['exit_code']}")
    elif not (report["is_complete"] and report["execution_successful"]
              and report["completeness_status"] == "complete"):
        reasons = ", ".join(report["ledger_reasons"]) or "no reason given"
        result.update(status="incomplete",
                      detail=f"analysis {report['completeness_status']}: {reasons}")
    else:
        result["status"] = "complete"
    return result


# ---------------------------------------------------------------------------
# Triage, gate and output
# ---------------------------------------------------------------------------

def apply_triage(results: list[dict], triage: dict) -> tuple[list[str], list[str]]:
    """Attach reviewed classifications. Returns (stale keys, keys whose occurrences changed).

    One key can cover several identical matches in a file. A triage entry records how many
    it reviewed; if the count changes, the entry no longer applies and must be re-reviewed,
    so a new occurrence cannot hide behind an old review.
    """
    used, changed = set(), []
    for target in results:
        for finding in target["findings"]:
            entry = triage.get(finding["key"])
            if not entry or entry["target"] != target["id"] or \
                    entry["rule_id"] != finding["rule_id"] or entry["file"] != finding["file"]:
                continue
            used.add(finding["key"])
            if entry["occurrences"] != finding["occurrences"]:
                changed.append(finding["key"])
                continue
            finding["triage"] = entry["classification"]
            finding["owner"] = entry["owner"]
    return sorted(set(triage) - used), sorted(changed)


def decide(results: list[dict], stale: list[str], changed: list[str] = ()) -> dict:
    reasons, warnings = [], []
    for target in results:
        if target["status"] != "complete":
            reasons.append(f"{target['id']}: {target['status']} ({target['detail']})")
        for f in target["findings"]:
            where = f"{target['id']}: {f['rule_id']} in {f['file']}:" \
                    f"{','.join(map(str, f['lines'])) or '?'}"
            if f["triage"] == "confirmed_risk":
                reasons.append(f"{where} is a confirmed_risk ({f['severity']})")
            elif f["triage"] in SUPPRESSING_CLASSES:
                continue
            elif f["severity"] in BLOCKING_SEVERITIES:
                label = "untriaged" if f["triage"] is None else f"unresolved {f['triage']}"
                reasons.append(f"{where} is {label} {f['severity']}")
            else:
                label = "untriaged" if f["triage"] is None else f["triage"]
                warnings.append(f"{where} is {label} {f['severity']}")
    warnings.extend(f"triage entry {key} matched no finding" for key in stale)
    warnings.extend(f"triage entry {key} reviewed a different number of occurrences; "
                    "re-review it" for key in changed)
    return {"passed": not reasons, "reasons": reasons, "warnings": warnings}


def _markdown(summary: dict) -> str:
    gate = summary["gate"]
    lines = [
        "# SkillSpector agent-skill scan (sanitized)", "",
        f"- SkillSpector {summary['tool']['version']} at commit `{summary['tool']['commit']}`",
        f"- Mode: {summary['mode']}; static only (LLM analysis off); outbound HTTP(S) blocked",
        f"- Generated: {summary['generated_at']}",
        f"- Gate verdict: **{'PASS' if gate['passed'] else 'FAIL'}**"
        + (" (report-only: not blocking)" if summary["mode"] == "report" else ""), "",
        "This report lists rule ids, files, lines and finding keys only. It contains no",
        "matched text or code snippets. A low score is not proof that a skill is safe.", "",
        "| Target | Kind | Files | Status | Score | Recommendation | Findings |",
        "|---|---|---|---|---|---|---|",
    ]
    for t in summary["targets"]:
        lines.append(f"| `{t['path']}` | {t['kind']} | {t['files']} | {t['status']} | "
                     f"{t.get('score', '-')} | {t.get('recommendation', '-')} | "
                     f"{len(t['findings'])} |")
    lines += ["", "## Findings", "",
              "| Target | Rule | Category | Severity | File:lines | Matches | Key | Triage |",
              "|---|---|---|---|---|---|---|---|"]
    for t in summary["targets"]:
        for f in t["findings"]:
            lines.append(f"| {t['id']} | {f['rule_id']} | {f['category']} | {f['severity']} | "
                         f"`{f['file']}`:{','.join(map(str, f['lines']))} | {f['occurrences']} | "
                         f"`{f['key']}` | "
                         f"{f['triage'] or 'untriaged'} |")
    lines += ["", "## Gate reasons", ""] + [f"- {r}" for r in gate["reasons"] or ["none"]]
    lines += ["", "## Warnings", ""] + [f"- {w}" for w in gate["warnings"] or ["none"]]
    if summary["exclusions"]:
        lines += ["", "## Not scanned (recorded exclusions)", ""]
        lines += [f"- `{e['path']}`: {e['reason']}" for e in summary["exclusions"]]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--scanner", required=True, type=Path,
                        help="the pinned skillspector executable")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    parser.add_argument("--triage", type=Path, default=DEFAULT_TRIAGE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--mode", choices=("report", "gate"), default="report")
    args = parser.parse_args(argv)

    try:
        policy = load_policy(args.policy, args.triage, args.repo_root)
        triage = load_triage(args.triage, policy)
        command = scanner_command(args.scanner)
    except PolicyError as exc:
        print(f"skill_scan: configuration error: {exc}", file=sys.stderr)
        return 2

    results = [scan_target(t, policy, command) for t in policy["targets"]]
    stale, changed = apply_triage(results, triage)
    gate = decide(results, stale, changed)
    summary = {
        "tool": {"name": "SkillSpector", "version": policy["version"],
                 "commit": policy["commit"]},
        "mode": args.mode, "llm_used": False, "network": "blocked (dead local proxy)",
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "limits": policy["limits"], "targets": results, "exclusions": policy["exclusions"],
        "stale_triage": stale, "changed_triage": changed, "gate": gate,
    }
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "skillspector-summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (args.out / "skillspector-summary.md").write_text(_markdown(summary), encoding="utf-8")

    for t in results:
        counts = {s: sum(f["severity"] == s for f in t["findings"]) for s in SEVERITIES}
        print(f"{t['id']}: {t['status']} files={t['files']} "
              + " ".join(f"{s}={n}" for s, n in counts.items() if n))
    print(f"gate: {'PASS' if gate['passed'] else 'FAIL'}"
          + (" (report-only)" if args.mode == "report" else ""))
    for reason in gate["reasons"]:
        print(f"  - {reason}")
    if args.mode == "report":
        return 0
    return 0 if gate["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
