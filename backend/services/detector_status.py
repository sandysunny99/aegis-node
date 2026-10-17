"""
Aegis Node — what each detector is actually doing in this deployment.

Feeds GET /health/detectors so the UI and the paper can say exactly which layers
ran in the active profile, instead of hard-coded claims such as "YARA: Enabled".
Never includes key or token values.
"""

from config import settings

from scanner import heuristics
from scanner.yara_scanner import yara_scanner


def _entry(name: str, layer: str, enabled: bool, available: bool,
           version: str | None = None, last_error: str | None = None, **extra) -> dict:
    return {
        "name": name,
        "layer": layer,
        "enabled": enabled,
        "available": bool(enabled and available),
        "version": version,
        "last_error": last_error,
        **extra,
    }


def _configured(flag: bool, key: str | None) -> bool:
    return bool(flag) and bool((key or "").strip())


def detector_report(av_status: dict) -> dict:
    """Profile, per-detector state, storage and database persistence."""
    av_provider = av_status.get("av_provider", "unknown")
    av_enabled = av_provider not in ("none", "invalid", "unknown")
    heur_on = heuristics.heuristics_enabled()
    yara_on = bool(settings.enable_yara)
    yara_loaded = yara_scanner.is_available and yara_scanner.rules is not None

    detectors = [
        _entry(
            "clamav", "L1", av_enabled, bool(av_status.get("av_available")),
            version=av_status.get("av_version"),
            last_error=None if av_status.get("av_available") or not av_enabled else "unreachable",
            provider=av_provider,
            remote_gateway=bool(settings.clamav_api_token),
            mock=bool(av_status.get("av_mock_mode")),
        ),
        _entry("yara", "L1", yara_on, yara_loaded,
               version=f"{yara_scanner.rules_loaded} rule files" if yara_loaded else None,
               last_error=None if yara_loaded or not yara_on else "rules not loaded"),
        _entry("content_rules", "L2", True, True, version="built-in"),
        _entry("encoding_normalization", "L2", bool(settings.enable_encoding_normalization), True),
        _entry("heuristics", "L3", heur_on, True),
        _entry("libmagic", "L3", heur_on, heuristics._HAS_MAGIC,
               last_error=None if heuristics._HAS_MAGIC or not heur_on else "libmagic not loaded"),
        _entry("pefile", "L3", heur_on, heuristics._HAS_PEFILE,
               last_error=None if heuristics._HAS_PEFILE or not heur_on else "pefile not installed"),
        _entry("virustotal", "L4", _configured(settings.enable_virustotal, settings.virustotal_api_key),
               True, lookup="sha256 only"),
        _entry("urlhaus", "L4", _configured(settings.enable_urlhaus, settings.urlhaus_auth_key),
               True, lookup="URLs only"),
        _entry("abuseipdb", "L4", _configured(settings.enable_abuseipdb, settings.abuseipdb_api_key),
               True, lookup="public IPs only"),
    ]

    db_url = settings.database_url or ""
    db_kind = db_url.split(":", 1)[0] if db_url else "unknown"
    return {
        "profile": settings.aegis_profile,
        "detectors": detectors,
        "storage": {
            "backend": "r2" if settings.r2_enabled else "local",
            # Local disk persists only where a volume is mounted; Render free has none.
            "persistent": bool(settings.r2_enabled) or settings.aegis_profile == "full",
        },
        "database": {
            "kind": db_kind,
            "persistent": db_kind != "sqlite" or settings.aegis_profile == "full",
        },
    }
