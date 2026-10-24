"""
The committed SkillSpector records must agree with each other.

security/skill_scan_triage.json, reports/security/skillspector-{baseline,after-triage}.*
and the totals lines in docs/security/SKILLSPECTOR_INTEGRATION_AUDIT.md were once out of
step (the audit said 8 false positives / 5 accepted risks while the triage file had 6 / 7).
These checks fail whenever one of them is edited without the others.
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True

import skill_scan  # noqa: E402

AUDIT = ROOT / "docs" / "security" / "SKILLSPECTOR_INTEGRATION_AUDIT.md"
REPORTS = ROOT / "reports" / "security"
CLASSES = ("false_positive", "accepted_risk", "confirmed_risk", "likely_risk",
           "incomplete_analysis")
TOTALS_RE = (r"{label} totals \([^)]*\)[^:]*: (\d+) findings \((\d+) matches\): (\d+) critical, "
             r"(\d+) high, (\d+) medium, (\d+) low; (\d+) false positives, (\d+) accepted risks, "
             r"(\d+) confirmed, (\d+) likely, (\d+) incomplete\.")


def _policy_and_triage():
    policy = skill_scan.load_policy(skill_scan.DEFAULT_POLICY, skill_scan.DEFAULT_TRIAGE, ROOT)
    return policy, skill_scan.load_triage(skill_scan.DEFAULT_TRIAGE, policy)


def _findings(name):
    summary = json.loads((REPORTS / f"skillspector-{name}.json").read_text(encoding="utf-8"))
    return summary, [(t["id"], f) for t in summary["targets"] for f in t["findings"]]


def _stated(label):
    text = " ".join(AUDIT.read_text(encoding="utf-8").split())
    match = re.search(TOTALS_RE.format(label=label), text)
    assert match, f"'{label} totals' line missing or reworded in {AUDIT.name}"
    return [int(n) for n in match.groups()]


def _computed(findings, triage, matches):
    sev = Counter(f["severity"] for _, f in findings)
    cls = Counter(triage[f["key"]]["classification"] for _, f in findings)
    return [len(findings), matches, sev["CRITICAL"], sev["HIGH"], sev["MEDIUM"], sev["LOW"],
            *(cls[c] for c in CLASSES)]


def test_triage_file_is_valid_and_every_entry_is_owner_approved():
    _, triage = _policy_and_triage()
    assert len(triage) == 14
    for entry in triage.values():
        assert entry["owner"] == "Sandeep (owner-approved 2026-10-24)", entry["key"]


def test_after_triage_report_matches_triage_file_exactly():
    policy, triage = _policy_and_triage()
    summary, findings = _findings("after-triage")
    assert summary["tool"]["version"] == policy["version"]
    assert summary["tool"]["commit"] == policy["commit"]
    assert summary["gate"]["passed"] is True
    assert not summary["stale_triage"] and not summary["changed_triage"]
    assert all(t["status"] == "complete" for t in summary["targets"])
    assert [t["id"] for t in summary["targets"]] == [t["id"] for t in policy["targets"]]
    assert sorted(f["key"] for _, f in findings) == sorted(triage)
    for target_id, f in findings:
        entry = triage[f["key"]]
        assert (entry["target"], entry["rule_id"], entry["file"]) == \
            (target_id, f["rule_id"], f["file"])
        assert entry["occurrences"] == f["occurrences"]
        assert f["triage"] == entry["classification"]


def test_audit_current_totals_match_after_triage_report():
    _, triage = _policy_and_triage()
    _, findings = _findings("after-triage")
    matches = sum(f["occurrences"] for _, f in findings)
    assert _stated("Current") == _computed(findings, triage, matches)


def test_audit_baseline_totals_match_baseline_report():
    # The first run predates the occurrence count; SkillSpector reported PE2 twice on
    # ci.yml:25 (one row here), so it had one more match than grouped rows.
    _, triage = _policy_and_triage()
    _, findings = _findings("baseline")
    assert all(f["key"] in triage for _, f in findings), "baseline key without triage entry"
    matches = sum(triage[f["key"]]["occurrences"] for _, f in findings)
    assert _stated("Baseline") == _computed(findings, triage, matches)


def test_markdown_reports_list_every_finding_once():
    for name in ("baseline", "after-triage"):
        _, findings = _findings(name)
        md = (REPORTS / f"skillspector-{name}.md").read_text(encoding="utf-8")
        for _, f in findings:
            assert md.count(f"`{f['key']}`") == 1, (name, f["key"])
