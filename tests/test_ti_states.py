"""
B3 / Phase H: provider results have explicit states, "not found" is never benign,
and an optional threat-intel outage is a separate enrichment status that never
changes the local verdict.
"""

import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from schemas import ThreatIntelResult

client = TestClient(app, raise_server_exceptions=False)
URL_CSV = b"id,link\n1,http://evil.example/x\n"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def urlhaus(monkeypatch):
    from config import settings

    monkeypatch.setattr(settings, "enable_urlhaus", True)
    monkeypatch.setattr(settings, "urlhaus_auth_key", "test-key")

    def respond(status: str):
        async def fake(url: str) -> ThreatIntelResult:
            return ThreatIntelResult(provider="urlhaus", indicator_type="url", indicator=url,
                                     status=status, source="URLhaus")
        monkeypatch.setattr("services.threat_intelligence.enrichment.lookup_url", fake)

    return respond


def _scan(payload=URL_CSV, name="d.csv") -> dict:
    up = client.post("/api/v1/datasets/upload", files={"file": (name, payload, "text/csv")})
    assert up.status_code == 201, up.text
    res = client.post(f"/api/v1/datasets/{up.json()['dataset_id']}/scan")
    assert res.status_code == 200, res.text
    return res.json()


def _urlhaus(scan):
    return [e for e in scan["threat_intel"]["evidence"] if e["provider"] == "urlhaus"]


@pytest.mark.parametrize(("status", "state"), [
    ("not_found", "NO_MATCH"),
    ("malicious", "MATCH"),
    ("timeout", "TIMEOUT"),
    ("rate_limited", "RATE_LIMITED"),
    ("unauthorized", "UNAUTHORIZED"),
    ("provider_error", "UNAVAILABLE"),
])
def test_urlhaus_results_have_explicit_states(urlhaus, status, state):
    urlhaus(status)
    [ev] = _urlhaus(_scan())
    assert ev["result_state"] == state


def test_urlhaus_not_found_is_unknown_not_benign(urlhaus):
    urlhaus("not_found")
    [ev] = _urlhaus(_scan())
    assert ev["reputation"] == "unknown"


def test_enrichment_status_is_separate_from_the_verdict(urlhaus, monkeypatch):
    urlhaus("timeout")
    scan = _scan()
    assert scan["enrichment_status"] == "UNAVAILABLE"
    assert scan["threat_intel"]["enrichment_status"] == "UNAVAILABLE"
    assert scan["verdict"] in ("clean_verified", "clean_with_limitations")  # local verdict unchanged


def test_enrichment_disabled_when_no_provider_is_configured():
    scan = _scan(b"id,name\n1,Alice\n")
    assert scan["enrichment_status"] == "DISABLED"


def test_partial_enrichment_when_one_provider_fails(urlhaus, monkeypatch):
    from config import settings

    urlhaus("not_found")
    monkeypatch.setattr(settings, "enable_virustotal", True)
    monkeypatch.setattr(settings, "virustotal_api_key", "test-key")

    async def vt_down(sha256):
        return ThreatIntelResult(provider="virustotal", indicator_type="file_hash", indicator=sha256,
                                 status="timeout", source="VirusTotal")
    monkeypatch.setattr("services.threat_intelligence.enrichment.lookup_file_hash", vt_down)
    assert _scan()["enrichment_status"] == "PARTIAL"


def test_no_match_cannot_cancel_a_local_malicious_finding(urlhaus):
    urlhaus("not_found")
    scan = _scan(b"id,link,payload\n1,http://evil.example/x," + EICAR + b"\n")
    assert scan["verdict"] == "malicious"
