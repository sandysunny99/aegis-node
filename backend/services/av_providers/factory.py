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

def get_av_provider() -> AntivirusProvider:
    provider = settings.av_provider.lower().strip()
    
    if provider == "metadefender":
        return MetaDefenderProvider(
            api_key=settings.metadefender_api_key,
            base_url=settings.metadefender_base_url
        )
    elif provider == "clamav_rest":
        return ClamAVRestProvider(
            api_url=settings.clamav_api_url,
            mock_mode=settings.clamav_mock_mode
        )
    elif provider == "none":
        return InvalidProvider("none")
    else:
        logger.error(f"Unknown AV provider '{provider}' configured! Falling back to safe unavailable state.")
        return InvalidProvider(provider)

