"""
Aegis Node - Threat Intelligence Deterministic Fusion Layer.
Combines and normalizes evidence from multiple external providers.
"""

from typing import List, Tuple
from backend.schemas import NormalizedTIEvidence, TIFusionReport

def _fuse_evidence(evidence_list: List[NormalizedTIEvidence], providers_checked: List[str]) -> Tuple[str, List[str], List[str]]:
    """
    Applies deterministic fusion rules to a list of normalized evidence.
    Returns:
      evidence_strength (str)
      limitations (list)
      conflicts (list)
    """
    limitations = []
    conflicts = []

    malicious_providers = set()
    suspicious_providers = set()
    benign_providers = set()
    unavailable_providers = set()

    for ev in evidence_list:
        if ev.error_status:
            unavailable_providers.add(ev.provider)
            limitations.append(f"{ev.provider.upper()}_UNAVAILABLE_{ev.error_status.upper()}")
            continue

        if ev.reputation == "malicious":
            malicious_providers.add(ev.provider)
        elif ev.reputation == "suspicious":
            suspicious_providers.add(ev.provider)
        elif ev.reputation == "benign":
            benign_providers.add(ev.provider)

    total_reporting = len(malicious_providers) + len(suspicious_providers) + len(benign_providers)

    # Determine strength
    strength = "NONE"

    if total_reporting == 0:
        if unavailable_providers:
            strength = "PROVIDER_UNAVAILABLE"
    elif total_reporting == 1:
        strength = "SINGLE_PROVIDER"
    else:
        # Multiple providers gave valid answers
        # Check for conflicts
        is_conflict = False
        if len(malicious_providers) > 0 and len(benign_providers) > 0:
            is_conflict = True

        if is_conflict:
            strength = "CONFLICTED"
            conflicts.append("TI_EVIDENCE_DISAGREEMENT")
        else:
            # They agree on malicious/suspicious/benign or some overlap without direct contradiction
            strength = "CORROBORATED"

    return strength, limitations, conflicts

def fuse_reports(evidence_list: List[NormalizedTIEvidence], providers_checked: List[str]) -> TIFusionReport:
    """
    Constructs a TIFusionReport from gathered evidence.
    """
    if not providers_checked:
        return TIFusionReport(
            status="disabled",
            evidence=[],
            evidence_strength="NONE",
            providers_checked=[],
            limitations=[],
            conflicts=[]
        )

    strength, limitations, conflicts = _fuse_evidence(evidence_list, providers_checked)

    # If all checked providers failed, status is degraded
    # If some failed and some succeeded, still degraded
    # If all succeeded, active
    status = "active"
    error_count = sum(1 for e in evidence_list if e.error_status)
    if error_count > 0:
        if error_count >= len(providers_checked):
            status = "error"  # All failed
        else:
            status = "degraded"

    return TIFusionReport(
        status=status,
        evidence=evidence_list,
        evidence_strength=strength,
        providers_checked=providers_checked,
        limitations=limitations,
        conflicts=conflicts
    )

def evaluate_local_verdict_conflict(local_verdict: str, ti_report: TIFusionReport) -> str | None:
    """
    Determines if the deterministic local verdict conflicts with the TI fusion report.
    Returns a conflict string if one exists, otherwise None.
    Does NOT modify the local verdict.
    """
    has_ti_malicious = any(e.reputation == "malicious" for e in ti_report.evidence if not e.error_status)

    if has_ti_malicious and local_verdict in ("clean_verified", "clean_with_limitations"):
        return "CONFLICT_TI_MALICIOUS"

    return None
