"""
MalwareBazaar, ThreatFox and CIRCL hashlookup: lookup-only, off by default, every
result state explicit, bounded responses, cached answers, never a clean verdict
from a no-match or an outage, and a known-good match never downgrades a local finding.
"""

import asyncio
import hashlib

import httpx
import pytest
from database import Base, create_all_tables, engine
from fastapi.testclient import TestClient
from main import app
from services.threat_intelligence import lookups

SHA = hashlib.sha256(b"x").hexdigest()
client = TestClient(app, raise_server_exceptions=False)
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    from config import settings

    Base.metadata.drop_all(bind=engine)
    create_all_tables()
    lookups.clear_cache()
    for flag in ("enable_malwarebazaar", "enable_threatfox", "enable_circl_hashlookup"):
        monkeypatch.setattr(settings, flag, False)
    monkeypatch.setattr(settings, "abusech_auth_key", "test-abusech-key")
    yield
    Base.metadata.drop_all(bind=engine)


def _serve(monkeypatch, handler):
    seen: list[httpx.Request] = []

    def record(request):
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(lookups, "_TRANSPORT", httpx.MockTransport(record))
    return seen


def _enable(monkeypatch, *flags):
    from config import settings

    for flag in flags:
        monkeypatch.setattr(settings, flag, True)


def run(coro):
    return asyncio.run(coro)


# ─── disabled / missing key ──────────────────────────────────────────────────

def test_disabled_providers_send_nothing(monkeypatch):
    seen = _serve(monkeypatch, lambda r: httpx.Response(200, json={}))
    assert run(lookups.malwarebazaar_hash(SHA)) is None
    assert run(lookups.threatfox_hash(SHA)) is None
    assert run(lookups.circl_hash(SHA)) is None
    assert seen == []


def test_missing_abusech_key_disables_the_abusech_providers(monkeypatch):
    from config import settings

    _enable(monkeypatch, "enable_malwarebazaar", "enable_threatfox")
    monkeypatch.setattr(settings, "abusech_auth_key", "")
    monkeypatch.setattr(settings, "urlhaus_auth_key", "")
    seen = _serve(monkeypatch, lambda r: httpx.Response(200, json={}))
    assert run(lookups.malwarebazaar_hash(SHA)) is None
    assert seen == []


# ─── MalwareBazaar ───────────────────────────────────────────────────────────

def test_malwarebazaar_match(monkeypatch):
    _enable(monkeypatch, "enable_malwarebazaar")
    seen = _serve(monkeypatch, lambda r: httpx.Response(200, json={
        "query_status": "ok", "data": [{"sha256_hash": SHA, "signature": "AgentTesla", "tags": ["exe"]}]}))
    ev = run(lookups.malwarebazaar_hash(SHA))
    assert (ev.result_state, ev.reputation, ev.category) == ("MATCH", "malicious", "AgentTesla")
    [req] = seen
    assert req.method == "POST" and req.url.host == "mb-api.abuse.ch"
    assert req.headers["Auth-Key"] == "test-abusech-key"
    assert b"query=get_info" in req.content and b"get_file" not in req.content


def test_malwarebazaar_not_found_is_no_match_not_benign(monkeypatch):
    _enable(monkeypatch, "enable_malwarebazaar")
    _serve(monkeypatch, lambda r: httpx.Response(200, json={"query_status": "hash_not_found"}))
    ev = run(lookups.malwarebazaar_hash(SHA))
    assert (ev.result_state, ev.reputation) == ("NO_MATCH", "unknown")


# ─── ThreatFox ───────────────────────────────────────────────────────────────

def test_threatfox_hash_and_url(monkeypatch):
    _enable(monkeypatch, "enable_threatfox")

    def handler(request):
        body = request.read()
        if b"search_hash" in body:
            return httpx.Response(200, json={"query_status": "no_result"})
        return httpx.Response(200, json={"query_status": "ok", "data": [
            {"ioc": "http://evil.example/x", "malware_printable": "Dridex", "threat_type": "payload_delivery"}]})

    seen = _serve(monkeypatch, handler)
    assert run(lookups.threatfox_hash(SHA)).result_state == "NO_MATCH"
    ev = run(lookups.threatfox_url("http://evil.example/x"))
    assert (ev.result_state, ev.reputation, ev.category) == ("MATCH", "malicious", "Dridex")
    assert all(r.url.host == "threatfox-api.abuse.ch" for r in seen)
    assert b'"exact_match": true' in seen[-1].content or b'"exact_match":true' in seen[-1].content


# ─── CIRCL hashlookup ────────────────────────────────────────────────────────

def test_circl_known_file_is_an_annotation(monkeypatch):
    _enable(monkeypatch, "enable_circl_hashlookup")
    seen = _serve(monkeypatch, lambda r: httpx.Response(200, json={
        "FileName": "kernel32.dll", "source": "NSRL", "hashlookup:trust": 100}))
    ev = run(lookups.circl_hash(SHA))
    assert (ev.result_state, ev.reputation) == ("MATCH", "known_good")
    [req] = seen
    assert req.method == "GET" and req.url.host == "hashlookup.circl.lu"
    assert req.url.path == f"/lookup/sha256/{SHA}"


def test_circl_unknown_hash_is_no_match(monkeypatch):
    _enable(monkeypatch, "enable_circl_hashlookup")
    _serve(monkeypatch, lambda r: httpx.Response(404, json={"message": "Non existing SHA-256"}))
    assert run(lookups.circl_hash(SHA)).result_state == "NO_MATCH"


# ─── shared failure handling ─────────────────────────────────────────────────

@pytest.mark.parametrize(("response", "state"), [
    (lambda r: httpx.Response(401, json={}), "UNAUTHORIZED"),
    (lambda r: httpx.Response(403, json={}), "UNAUTHORIZED"),
    (lambda r: httpx.Response(429, json={}), "RATE_LIMITED"),
    (lambda r: httpx.Response(503, json={}), "UNAVAILABLE"),
    (lambda r: httpx.Response(200, text="<html>not json"), "INVALID_RESPONSE"),
    (lambda r: httpx.Response(200, json=["unexpected", "shape"]), "INVALID_RESPONSE"),
    (lambda r: httpx.Response(200, json={"query_status": "ok", "data": "not-a-list"}), "INVALID_RESPONSE"),
    (lambda r: httpx.Response(200, content=b'{"pad": "' + b"a" * (2 * 1024 * 1024) + b'"}'), "INVALID_RESPONSE"),
], ids=["401", "403", "429", "503", "not-json", "list-root", "bad-data", "oversized"])
def test_failures_have_explicit_states_and_are_not_cached(monkeypatch, response, state):
    _enable(monkeypatch, "enable_malwarebazaar")
    seen = _serve(monkeypatch, response)
    ev = run(lookups.malwarebazaar_hash(SHA))
    assert ev.result_state == state and ev.reputation == "unknown"
    assert ev.error_status is not None
    run(lookups.malwarebazaar_hash(SHA))
    assert len(seen) == 2  # failures are retried next time, not cached


def test_timeout_and_connection_errors(monkeypatch):
    _enable(monkeypatch, "enable_circl_hashlookup")

    def slow(request):
        raise httpx.ReadTimeout("slow", request=request)
    _serve(monkeypatch, slow)
    assert run(lookups.circl_hash(SHA)).result_state == "TIMEOUT"

    def down(request):
        raise httpx.ConnectError("refused", request=request)
    _serve(monkeypatch, down)
    assert run(lookups.circl_hash(SHA)).result_state == "UNAVAILABLE"


def test_answers_are_cached(monkeypatch):
    _enable(monkeypatch, "enable_circl_hashlookup")
    seen = _serve(monkeypatch, lambda r: httpx.Response(404, json={}))
    run(lookups.circl_hash(SHA))
    run(lookups.circl_hash(SHA))
    assert len(seen) == 1


def test_invalid_hash_is_never_sent(monkeypatch):
    _enable(monkeypatch, "enable_malwarebazaar", "enable_circl_hashlookup")
    seen = _serve(monkeypatch, lambda r: httpx.Response(200, json={}))
    assert run(lookups.malwarebazaar_hash("../../etc")) is None
    assert run(lookups.circl_hash("zz")) is None
    assert seen == []


# ─── through a real scan ─────────────────────────────────────────────────────

def _scan(payload) -> dict:
    up = client.post("/api/v1/datasets/upload", files={"file": ("d.csv", payload, "text/csv")})
    return client.post(f"/api/v1/datasets/{up.json()['dataset_id']}/scan").json()


def test_known_good_never_downgrades_a_local_malicious_finding(monkeypatch):
    _enable(monkeypatch, "enable_circl_hashlookup")
    _serve(monkeypatch, lambda r: httpx.Response(200, json={"source": "NSRL", "hashlookup:trust": 100}))
    scan = _scan(b"id,payload\n1," + EICAR + b"\n")
    assert scan["verdict"] == "malicious"
    assert "circl_hashlookup" in scan["threat_intel"]["providers_checked"]


def test_external_match_on_a_clean_scan_is_a_conflict_not_a_verdict_change(monkeypatch):
    _enable(monkeypatch, "enable_malwarebazaar")
    _serve(monkeypatch, lambda r: httpx.Response(200, json={
        "query_status": "ok", "data": [{"signature": "X"}]}))
    scan = _scan(b"id,name\n1,Alice\n")
    assert scan["verdict"] in ("clean_verified", "clean_with_limitations")
    assert "CONFLICT_TI_MALICIOUS" in scan["verification_limitations"]


def test_outage_is_partial_enrichment_not_clean(monkeypatch):
    _enable(monkeypatch, "enable_malwarebazaar", "enable_circl_hashlookup")

    def handler(request):
        if request.url.host == "mb-api.abuse.ch":
            return httpx.Response(503)
        return httpx.Response(404, json={})
    _serve(monkeypatch, handler)
    assert _scan(b"id,name\n1,Alice\n")["enrichment_status"] == "PARTIAL"
