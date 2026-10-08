import logging
from backend.config import settings
from .base import AntivirusProvider
from .clamav import ClamAVRestProvider
from .metadefender import MetaDefenderProvider

logger = logging.getLogger(__name__)

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
    else:
        # Fallback to a stub provider or log warning and use ClamAV mock
        logger.warning(f"Unknown AV provider '{provider}', defaulting to ClamAV (Mock)")
        return ClamAVRestProvider(api_url="http://localhost:3000", mock_mode=True)
