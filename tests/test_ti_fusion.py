import pytest
from datetime import datetime

from backend.schemas import NormalizedTIEvidence, TIFusionReport
from backend.services.threat_intelligence.fusion import _fuse_evidence, fuse_reports, evaluate_local_verdict_conflict

def test_normalization_models():
    """Verify the normalized models match the expected structure."""
    ev = NormalizedTIEvidence(
        provider="urlhaus",
        indicator_type="url",
        indicator="http://example.com",
        reputation="malicious",
        severity="critical"
    )
    assert ev.provider == "urlhaus"
    assert ev.reputation == "malicious"

def test_fusion_no_evidence():
    """No TI evidence returns NONE strength."""
    strength, lims, confs = _fuse_evidence([], ["urlhaus", "abuseipdb"])
    assert strength == "NONE"
    assert not lims
    assert not confs

def test_fusion_single_malicious():
    """Single provider malicious returns SINGLE_PROVIDER."""
    ev = NormalizedTIEvidence(provider="urlhaus", indicator_type="url", indicator="url", reputation="malicious", severity="critical")
    strength, lims, confs = _fuse_evidence([ev], ["urlhaus", "abuseipdb"])
    assert strength == "SINGLE_PROVIDER"
    assert not confs

def test_fusion_corroborated_malicious():
    """Multiple providers reporting malicious or suspicious without conflict returns CORROBORATED."""
    ev1 = NormalizedTIEvidence(provider="urlhaus", indicator_type="url", indicator="x", reputation="malicious", severity="critical")
    ev2 = NormalizedTIEvidence(provider="abuseipdb", indicator_type="ipv4", indicator="y", reputation="suspicious", severity="high")
    strength, lims, confs = _fuse_evidence([ev1, ev2], ["urlhaus", "abuseipdb"])
    assert strength == "CORROBORATED"
    assert not confs

def test_fusion_disagreement():
    """One malicious and one benign returns CONFLICTED."""
    ev1 = NormalizedTIEvidence(provider="urlhaus", indicator_type="url", indicator="x", reputation="malicious", severity="critical")
    ev2 = NormalizedTIEvidence(provider="abuseipdb", indicator_type="ipv4", indicator="y", reputation="benign", severity="informational")
    strength, lims, confs = _fuse_evidence([ev1, ev2], ["urlhaus", "abuseipdb"])
    assert strength == "CONFLICTED"
    assert "TI_EVIDENCE_DISAGREEMENT" in confs

def test_fusion_unavailable():
    """TI unavailable returns PROVIDER_UNAVAILABLE if no successful reports exist."""
    ev = NormalizedTIEvidence(provider="urlhaus", indicator_type="url", indicator="x", reputation="unknown", severity="informational", error_status="timeout")
    strength, lims, confs = _fuse_evidence([ev], ["urlhaus", "abuseipdb"])
    assert strength == "PROVIDER_UNAVAILABLE"
    assert "URLHAUS_UNAVAILABLE_TIMEOUT" in lims

def test_conflict_local_clean_ti_malicious():
    """TI says malicious while local scanner says clean_verified -> CONFLICT_TI_MALICIOUS."""
    ev = NormalizedTIEvidence(provider="urlhaus", indicator_type="url", indicator="x", reputation="malicious", severity="critical")
    report = fuse_reports([ev], ["urlhaus", "abuseipdb"])
    
    conflict = evaluate_local_verdict_conflict("clean_verified", report)
    assert conflict == "CONFLICT_TI_MALICIOUS"

def test_conflict_local_clean_ti_suspicious():
    """TI says suspicious while local scanner says clean_verified -> No conflict."""
    ev = NormalizedTIEvidence(provider="abuseipdb", indicator_type="ipv4", indicator="x", reputation="suspicious", severity="high")
    report = fuse_reports([ev], ["urlhaus", "abuseipdb"])
    
    conflict = evaluate_local_verdict_conflict("clean_verified", report)
    assert conflict is None

def test_conflict_local_malicious_ti_unavailable():
    """Local malicious + TI unavailable -> No conflict."""
    ev = NormalizedTIEvidence(provider="urlhaus", indicator_type="url", indicator="x", reputation="unknown", severity="informational", error_status="timeout")
    report = fuse_reports([ev], ["urlhaus", "abuseipdb"])
    
    conflict = evaluate_local_verdict_conflict("malicious", report)
    assert conflict is None
