"""
YARAify (hash lookup, abuse.ch key) and urlscan.io (search existing scans of a URL):
lookup-only, off without a flag and key, never a file upload or a scan submission,
every outcome an explicit result state. Also the dashboard key names URL_HAUS_KEY
and URLSCAN_KEY used on Render.
"""

import asyncio
import hashlib
import json

import httpx
import pytest
from config import Settings, settings
from services.threat_intelligence import lookups

SHA = hashlib.sha256(b"x").hexdigest()
URL = "http://bad.example.org/payload"
SCAN_ID = "0199a1b2-c3d4-4e5f-8a9b-0c1d2e3f4a5b"


@pytest.fixture(autouse=True)
def isolated(monkeypatch):
    lookups.clear_cache()
    for flag in ("enable_malwarebazaar", "enable_threatfox", "enable_circl_hashlookup",
                 "enable_yaraify", "enable_urlscan", "enable_hybrid_analysis", "enable_otx"):
        monkeypatch.setattr(settings, flag, False)
    monkeypatch.setattr(settings, "abusech_auth_key", "test-abusech-key")
    monkeypatch.setattr(settings, "urlscan_api_key", "test-urlscan-key")
    yield
    lookups.clear_cache()


def _serve(monkeypatch, handler):
    seen: list[httpx.Request] = []

    def record(request):
        seen.append(request)
        return handler(request)

    monkeypatch.setattr(lookups, "_TRANSPORT", httpx.MockTransport(record))
    return seen


def run(coro):
    return asyncio.run(coro)


def test_off_by_default_and_without_key(monkeypatch):
    seen = _serve(monkeypatch, lambda r: httpx.Response(500))
    assert run(lookups.yaraify_hash(SHA)) is None
    assert run(lookups.urlscan_url(URL)) is None
    monkeypatch.setattr(settings, "enable_urlscan", True)
    monkeypatch.setattr(settings, "urlscan_api_key", "")
    assert run(lookups.urlscan_url(URL)) is None
    assert seen == []


# ─── YARAify ─────────────────────────────────────────────────────────────────

def _yaraify(monkeypatch, body, status=200):
    monkeypatch.setattr(settings, "enable_yaraify", True)
    return _serve(monkeypatch, lambda r: httpx.Response(status, json=body))


def test_yaraify_sends_only_the_hash(monkeypatch):
    seen = _yaraify(monkeypatch, {"query_status": "hash_not_found"})
    ev = run(lookups.yaraify_hash(SHA))
    assert ev.result_state == "NO_MATCH"
    req = seen[0]
    assert str(req.url) == "https://yaraify-api.abuse.ch/api/v1/"
    assert req.headers["Auth-Key"] == "test-abusech-key"
    assert json.loads(req.content) == {"query": "lookup_hash", "search_term": SHA}


def test_yaraify_rule_hit_is_a_match(monkeypatch):
    _yaraify(monkeypatch, {"query_status": "ok", "data": {"metadata": {}, "tasks": [
        {"clamav_results": [], "static_results": [{"rule_name": "win_emotet_auto"}]}]}})
    ev = run(lookups.yaraify_hash(SHA))
    assert ev.result_state == "MATCH"
    assert ev.reputation == "malicious"
    assert ev.category == "yara:win_emotet_auto"


def test_yaraify_record_without_hits_is_no_match(monkeypatch):
    _yaraify(monkeypatch, {"query_status": "ok", "data": {"tasks": [{"clamav_results": [], "static_results": []}]}})
    assert run(lookups.yaraify_hash(SHA)).result_state == "NO_MATCH"


@pytest.mark.parametrize(("body", "status", "state"), [
    ({"query_status": "unknown_auth_key"}, 200, "UNAUTHORIZED"),
    ({"query_status": "ok", "data": []}, 200, "INVALID_RESPONSE"),
    ({}, 429, "RATE_LIMITED"),
    ({}, 503, "UNAVAILABLE"),
])
def test_yaraify_failures_are_never_no_match(monkeypatch, body, status, state):
    _yaraify(monkeypatch, body, status)
    assert run(lookups.yaraify_hash(SHA)).result_state == state


# ─── urlscan.io ──────────────────────────────────────────────────────────────

def _urlscan(monkeypatch, results, verdicts, search_status=200):
    monkeypatch.setattr(settings, "enable_urlscan", True)

    def handler(request):
        if request.url.path == "/api/v1/search/":
            return httpx.Response(search_status, json={"results": results, "total": len(results)})
        if request.url.path == f"/api/v1/result/{SCAN_ID}/":
            return httpx.Response(200, json={"verdicts": verdicts})
        return httpx.Response(404)
    return _serve(monkeypatch, handler)


def test_urlscan_only_searches_never_submits(monkeypatch):
    seen = _urlscan(monkeypatch, [{"_id": SCAN_ID}], {"urlscan": {"score": 0}})
    assert run(lookups.urlscan_url(URL)).result_state == "NO_MATCH"
    assert [r.method for r in seen] == ["GET", "GET"]
    assert all("/scan" not in r.url.path for r in seen)
    assert seen[0].headers["API-Key"] == "test-urlscan-key"
    assert seen[0].url.params["q"] == f'page.url:"{URL}"'


def test_urlscan_malicious_verdict_is_a_match(monkeypatch):
    _urlscan(monkeypatch, [{"_id": SCAN_ID}], {"urlscan": {"score": 100, "categories": ["phishing"]}})
    ev = run(lookups.urlscan_url(URL))
    assert (ev.result_state, ev.category) == ("MATCH", "phishing")
    assert ev.reference_url == f"https://urlscan.io/result/{SCAN_ID}/"


def test_urlscan_overall_flag_is_a_match(monkeypatch):
    _urlscan(monkeypatch, [{"_id": SCAN_ID}], {"overall": {"malicious": True, "score": 10}})
    assert run(lookups.urlscan_url(URL)).result_state == "MATCH"


def test_urlscan_never_scanned_is_no_match(monkeypatch):
    seen = _urlscan(monkeypatch, [], {})
    assert run(lookups.urlscan_url(URL)).result_state == "NO_MATCH"
    assert len(seen) == 1


def test_urlscan_bad_key_is_unauthorized(monkeypatch):
    _urlscan(monkeypatch, [], {}, search_status=401)
    assert run(lookups.urlscan_url(URL)).result_state == "UNAUTHORIZED"


def test_urlscan_rejects_a_strange_scan_id(monkeypatch):
    _urlscan(monkeypatch, [{"_id": "../../admin"}], {})
    assert run(lookups.urlscan_url(URL)).result_state == "INVALID_RESPONSE"


# ─── Render dashboard key names ──────────────────────────────────────────────

def test_dashboard_key_names_are_read(monkeypatch):
    monkeypatch.setenv("URL_HAUS_KEY", "abusech-from-dashboard")
    monkeypatch.setenv("URLSCAN_KEY", "urlscan-from-dashboard")
    cfg = Settings(_env_file=None, urlhaus_auth_key=None, urlscan_api_key=None)
    assert cfg.urlhaus_auth_key == "abusech-from-dashboard"
    assert cfg.urlscan_api_key == "urlscan-from-dashboard"


# ─── Hybrid Analysis ─────────────────────────────────────────────────────────

def _ha(monkeypatch, body, status=200):
    monkeypatch.setattr(settings, "enable_hybrid_analysis", True)
    monkeypatch.setattr(settings, "hybrid_analysis_api_key", "test-ha-key")
    return _serve(monkeypatch, lambda r: httpx.Response(status, json=body))


def test_hybrid_analysis_off_without_key(monkeypatch):
    monkeypatch.setattr(settings, "enable_hybrid_analysis", True)
    monkeypatch.setattr(settings, "hybrid_analysis_api_key", "")
    seen = _serve(monkeypatch, lambda r: httpx.Response(500))
    assert run(lookups.hybrid_analysis_hash(SHA)) is None
    assert seen == []


def test_hybrid_analysis_only_reads_the_overview(monkeypatch):
    seen = _ha(monkeypatch, {}, status=404)
    assert run(lookups.hybrid_analysis_hash(SHA)).result_state == "NO_MATCH"
    req = seen[0]
    assert req.method == "GET"
    assert str(req.url) == f"https://hybrid-analysis.com/api/v2/overview/{SHA}"
    assert req.headers["api-key"] == "test-ha-key"
    assert req.headers["User-Agent"] == "Falcon Sandbox"


@pytest.mark.parametrize(("verdict", "state", "reputation"), [
    ("malicious", "MATCH", "malicious"),
    ("suspicious", "MATCH", "suspicious"),
    ("whitelisted", "MATCH", "known_good"),
    ("no specific threat", "NO_MATCH", "unknown"),
    (None, "NO_MATCH", "unknown"),
])
def test_hybrid_analysis_verdicts(monkeypatch, verdict, state, reputation):
    _ha(monkeypatch, {"sha256": SHA, "verdict": verdict, "threat_score": 90, "vx_family": "Emotet"})
    ev = run(lookups.hybrid_analysis_hash(SHA))
    assert (ev.result_state, ev.reputation) == (state, reputation)


def test_hybrid_analysis_rejected_key_is_unauthorized(monkeypatch):
    _ha(monkeypatch, {"message": "Your API key is incompatible with API v2."}, status=403)
    assert run(lookups.hybrid_analysis_hash(SHA)).result_state == "UNAUTHORIZED"


# ─── AlienVault OTX ──────────────────────────────────────────────────────────

def _otx(monkeypatch, body, status=200):
    monkeypatch.setattr(settings, "enable_otx", True)
    monkeypatch.setattr(settings, "otx_api_key", "test-otx-key")
    return _serve(monkeypatch, lambda r: httpx.Response(status, json=body))


def test_otx_reads_the_general_record(monkeypatch):
    seen = _otx(monkeypatch, {"pulse_info": {"count": 0, "pulses": []}, "validation": []})
    assert run(lookups.otx_hash(SHA)).result_state == "NO_MATCH"
    req = seen[0]
    assert req.method == "GET"
    assert str(req.url) == f"https://otx.alienvault.com/api/v1/indicators/file/{SHA}/general"
    assert req.headers["X-OTX-API-KEY"] == "test-otx-key"


def test_otx_pulses_are_suspicious_not_malicious(monkeypatch):
    _otx(monkeypatch, {"pulse_info": {"count": 3, "pulses": [{"tags": ["qbot"]}],
                                      "related": {"alienvault": {"malware_families": ["Qakbot"]}}}})
    ev = run(lookups.otx_hash(SHA))
    assert (ev.result_state, ev.reputation, ev.category) == ("MATCH", "suspicious", "Qakbot")


def test_otx_whitelist_is_known_good(monkeypatch):
    _otx(monkeypatch, {"pulse_info": {"count": 1}, "validation": [{"source": "whitelist", "name": "x"}]})
    assert run(lookups.otx_hash(SHA)).reputation == "known_good"


def test_otx_url_is_path_encoded(monkeypatch):
    seen = _otx(monkeypatch, {"pulse_info": {"count": 0}})
    assert run(lookups.otx_url(URL)).result_state == "NO_MATCH"
    assert seen[0].url.raw_path.decode().startswith("/api/v1/indicators/url/http%3A%2F%2Fbad.example.org%2Fpayload/")


@pytest.mark.parametrize(("body", "status", "state"), [
    ({}, 403, "UNAUTHORIZED"), ({"detail": "x"}, 200, "INVALID_RESPONSE"), ({}, 503, "UNAVAILABLE"),
])
def test_otx_failures_are_explicit(monkeypatch, body, status, state):
    _otx(monkeypatch, body, status)
    assert run(lookups.otx_hash(SHA)).result_state == state
