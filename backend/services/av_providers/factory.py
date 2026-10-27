import logging

from config import settings

from .base import AntivirusProvider, AVScanResult
from .clamav import ClamAVRestProvider
from .metadefender import MetaDefenderProvider

logger = logging.getLogger(__name__)

class InvalidProvider(AntivirusProvider):
    def __init__(self, provider_name: str):
        self._name = provider_name

    @property
    def provider_name(self) -> str:
        return self._name

    @property
    def provider_authority(self) -> str:
        return "invalid"

    def ping(self) -> bool:
        return False

    def get_version(self) -> str:
        return "Invalid Provider Configuration"

    def scan_file(self, path: str) -> AVScanResult:
        return AVScanResult(
            available=False,
            infected=False,
            virus_name=None,
            raw_response="",
            error=f"Invalid AV provider configured: {self._name}"
        )

class FallbackAVProvider(AntivirusProvider):
    """
    Primary antivirus with a secondary used only when the primary gives no result.
    The result names the provider that produced it; if both give none, the primary's
    reason is kept, so "unreachable" is never reported as a hash miss or as clean.
    """

    def __init__(self, primary: AntivirusProvider, secondary: AntivirusProvider):
        self.primary = primary
        self.secondary = secondary

    @property
    def provider_name(self) -> str:
        return self.primary.provider_name

    @property
    def provider_authority(self) -> str:
        return self.primary.provider_authority

    @property
    def mock_mode(self) -> bool:
        return bool(getattr(self.primary, "mock_mode", False))

    def ping(self) -> bool:
        return self.primary.ping() or self.secondary.ping()

    def get_version(self) -> str:
        if self.primary.ping():
            return self.primary.get_version()
        return f"{self.secondary.get_version()} (fallback; {self.primary.provider_name} unreachable)"

    def scan_file(self, path: str) -> AVScanResult:
        first = self.primary.scan_file(path)
        first.provider = first.provider or self.primary.provider_name
        if first.available:
            return first
        logger.warning("%s gave no result (%s); trying %s", self.primary.provider_name,
                       first.error, self.secondary.provider_name)
        second = self.secondary.scan_file(path)
        second.provider = second.provider or self.secondary.provider_name
        return second if second.available else first


def _build(provider: str) -> AntivirusProvider:

    if provider == "metadefender":
        return MetaDefenderProvider(
            api_key=settings.metadefender_api_key,
            base_url=settings.metadefender_base_url,
            timeout_seconds=float(settings.metadefender_timeout_seconds),
        )
    elif provider == "clamav_rest":
        return ClamAVRestProvider(
            api_url=settings.clamav_api_url,
            mock_mode=settings.clamav_mock_mode,
            api_token=settings.clamav_api_token,
        )
    elif provider == "none":
        return InvalidProvider("none")
    else:
        logger.error(f"Unknown AV provider '{provider}' configured! Falling back to safe unavailable state.")
        return InvalidProvider(provider)


def get_av_provider() -> AntivirusProvider:
    primary_name = (settings.av_provider or "").lower().strip()
    fallback_name = (getattr(settings, "av_fallback_provider", "") or "").lower().strip()
    primary = _build(primary_name)
    if fallback_name and fallback_name not in ("none", primary_name):
        return FallbackAVProvider(primary, _build(fallback_name))
    return primary

