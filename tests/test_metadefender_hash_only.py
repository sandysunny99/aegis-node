"""
MetaDefender is hash-only (Phase A gap #17): the provider may send the file's
SHA-256 and nothing else. A hash MetaDefender has never seen is "unavailable",
never clean.
"""

import hashlib

import httpx
import pytest
from services.av_providers.metadefender import MetaDefenderProvider

PAYLOAD = b"id,secret_column\n1,patient-record-123\n"
SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture
def sample(tmp_path):
    f = tmp_path / "data.csv"
    f.write_bytes(PAYLOAD)
    return f


def _provider(handler, seen):
    def record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    return MetaDefenderProvider(api_key="test-key", transport=httpx.MockTransport(record))


def _hash_report(scan_all_result_i: int, threat: str | None = None) -> dict:
    details = {"EngineA": {"threat_found": threat or ""}}
    return {"scan_results": {"scan_all_result_i": scan_all_result_i, "scan_details": details}}


def test_only_the_hash_is_sent(sample):
    seen: list[httpx.Request] = []
    provider = _provider(lambda r: httpx.Response(200, json=_hash_report(0)), seen)
    provider.scan_file(str(sample))

    assert len(seen) == 1
    request = seen[0]
    assert request.method == "GET"
    assert request.url.path.endswith(f"/hash/{SHA256}")
    assert request.headers["apikey"] == "test-key"
    assert PAYLOAD not in request.content
    assert b"patient-record-123" not in request.content


def test_known_clean_hash_is_available_and_clean(sample):
    res = _provider(lambda r: httpx.Response(200, json=_hash_report(0)), []).scan_file(str(sample))
    assert (res.available, res.infected) == (True, False)


def test_known_infected_hash_is_infected(sample):
    handler = lambda r: httpx.Response(200, json=_hash_report(1, "EICAR-Test-File"))  # noqa: E731
    res = _provider(handler, []).scan_file(str(sample))
    assert (res.available, res.infected, res.virus_name) == (True, True, "EICAR-Test-File")


def test_unknown_hash_is_unavailable_not_clean(sample):
    res = _provider(lambda r: httpx.Response(404, json={"error": "not found"}), []).scan_file(str(sample))
    assert res.available is False
    assert res.infected is False
    assert res.error == "METADEFENDER_HASH_NOT_FOUND"


@pytest.mark.parametrize("code", [401, 403, 429, 500, 503])
def test_provider_errors_are_unavailable(sample, code):
    res = _provider(lambda r: httpx.Response(code, json={}), []).scan_file(str(sample))
    assert res.available is False
    assert res.infected is False
