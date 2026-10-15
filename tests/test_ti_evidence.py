"""
VirusTotal results are threat-intel evidence, not local findings (Phase A gap #9),
and the TI report lists only providers that are actually configured (gap #15).
"""

import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from schemas import ThreatIntelResult

client = TestClient(app, raise_server_exceptions=False)
CLEAN_CSV = b"id,name\n1,Alice\n2,Bob\n"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def vt(monkeypatch):
    """Configure VirusTotal and make the lookup return a chosen status."""
    from config import settings

    monkeypatch.setattr(settings, "enable_virustotal", True)
    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")

    def respond(status: str, **extra):
        async def fake_lookup(sha256: str) -> ThreatIntelResult:
            return ThreatIntelResult(
                provider="virustotal", indicator_type="file_hash", indicator=sha256,
                status=status, source="VirusTotal", **extra,
            )
        monkeypatch.setattr("services.threat_intelligence.enrichment.lookup_file_hash", fake_lookup)

    return respond


def _scan(payload: bytes = CLEAN_CSV) -> dict:
    up = client.post("/api/v1/datasets/upload", files={"file": ("d.csv", payload, "text/csv")})
    assert up.status_code == 201, up.text
    res = client.post(f"/api/v1/datasets/{up.json()['dataset_id']}/scan")
    assert res.status_code == 200, res.text
    return res.json()


def _vt_evidence(scan: dict) -> list[dict]:
    return [e for e in scan["threat_intel"]["evidence"] if e["provider"] == "virustotal"]


def test_virustotal_result_is_evidence_not_a_finding(vt):
    vt("malicious", malicious_count=12, confidence="12/70")
    scan = _scan()
    assert not [f for f in scan["findings"] if f["rule_id"].startswith("vt_")]
    [ev] = _vt_evidence(scan)
    assert (ev["indicator_type"], ev["reputation"], ev["error_status"]) == ("sha256", "malicious", None)
    assert "virustotal" in scan["threat_intel"]["providers_checked"]
    assert "CONFLICT_VT_MALICIOUS" in scan["verification_limitations"]


def test_virustotal_not_found_is_unknown_not_benign(vt):
    vt("not_found")
    [ev] = _vt_evidence(_scan())
    assert ev["reputation"] == "unknown"


def test_virustotal_auth_failure_is_a_limitation(vt):
    vt("unauthorized", error_message="VirusTotal auth error 401")
    scan = _scan()
    assert "VT_UNAVAILABLE_AUTH" in scan["verification_limitations"]
    [ev] = _vt_evidence(scan)
    assert ev["error_status"] == "unauthorized"


def test_unconfigured_providers_are_not_listed_as_checked():
    scan = _scan()
    ti = scan["threat_intel"]
    assert ti["providers_checked"] == []
    assert ti["status"] == "disabled"
    assert not [f for f in scan["findings"] if f["rule_id"].startswith("vt_")]
