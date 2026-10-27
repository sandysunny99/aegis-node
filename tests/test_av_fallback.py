"""AV_FALLBACK_PROVIDER: MetaDefender answers only when the Oracle ClamAV gateway gives no result."""

from config import settings
from services.av_providers import get_av_provider
from services.av_providers.base import AntivirusProvider, AVScanResult
from services.av_providers.factory import FallbackAVProvider


class _Fake(AntivirusProvider):
    def __init__(self, name, result, up=True):
        self._name, self._result, self._up, self.calls = name, result, up, 0

    @property
    def provider_name(self):
        return self._name

    @property
    def provider_authority(self):
        return "test"

    def ping(self):
        return self._up

    def get_version(self):
        return f"{self._name} 1.0"

    def scan_file(self, path):
        self.calls += 1
        return AVScanResult(**self._result)


CLEAN = dict(available=True, infected=False, virus_name=None, raw_response="", error=None)
DOWN = dict(available=False, infected=False, virus_name=None, raw_response="", error="connect timeout")
MISS = dict(available=False, infected=False, virus_name=None, raw_response="", error="METADEFENDER_HASH_NOT_FOUND")


def test_primary_result_is_used_and_fallback_not_called():
    clam, md = _Fake("clamav_rest", CLEAN), _Fake("metadefender", CLEAN)
    r = FallbackAVProvider(clam, md).scan_file("x")
    assert (r.available, r.provider, md.calls) == (True, "clamav_rest", 0)


def test_fallback_answers_when_primary_is_down():
    clam, md = _Fake("clamav_rest", DOWN, up=False), _Fake("metadefender", CLEAN)
    chain = FallbackAVProvider(clam, md)
    r = chain.scan_file("x")
    assert (r.available, r.provider) == (True, "metadefender")
    assert chain.ping() is True
    assert "fallback" in chain.get_version()


def test_both_without_result_keeps_the_primary_reason():
    clam, md = _Fake("clamav_rest", DOWN, up=False), _Fake("metadefender", MISS)
    r = FallbackAVProvider(clam, md).scan_file("x")
    assert r.available is False
    assert (r.provider, r.error) == ("clamav_rest", "connect timeout")


def test_factory_builds_the_chain_only_when_configured(monkeypatch):
    monkeypatch.setattr(settings, "av_provider", "clamav_rest")
    monkeypatch.setattr(settings, "av_fallback_provider", "")
    assert not isinstance(get_av_provider(), FallbackAVProvider)
    monkeypatch.setattr(settings, "av_fallback_provider", "metadefender")
    chain = get_av_provider()
    assert isinstance(chain, FallbackAVProvider)
    assert (chain.primary.provider_name, chain.secondary.provider_name) == ("clamav_rest", "metadefender")
    monkeypatch.setattr(settings, "av_fallback_provider", "clamav_rest")
    assert not isinstance(get_av_provider(), FallbackAVProvider)
