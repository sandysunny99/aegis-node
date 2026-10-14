"""Aegis Node Test Suite — conftest.py

Shared fixtures that apply to ALL test files.
"""
import atexit
import os
import shutil
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Hermetic environment (must run before any backend module is imported)
# ---------------------------------------------------------------------------
# config.Settings reads the developer's real .env. Environment variables take
# precedence over .env, so we pin everything the suite depends on here:
#  - artifacts and the SQLite DB live in a throwaway directory, never ./data
#  - provider keys are blanked so no test can reach Groq/NVIDIA/HF/Cloudflare
#    or threat-intel APIs with real credentials
#  - APP_ENV=test so production-only startup checks do not apply
_TEST_ROOT = Path(tempfile.mkdtemp(prefix="aegis_tests_"))
atexit.register(shutil.rmtree, _TEST_ROOT, ignore_errors=True)

_SECRET_ENV_VARS = (
    "API_KEY", "GEMINI_API_KEY", "FALLBACK_GEMINI_API_KEY", "GROQ_API_KEY",
    "FALLBACK_GROQ_API_KEY", "NVIDIA_API_KEY", "FALLBACK_NVIDIA_API_KEY", "HF_TOKEN",
    "FALLBACK_HF_TOKEN", "XAI_API_KEY", "FALLBACK_XAI_API_KEY", "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_API_TOKEN", "FALLBACK_CLOUDFLARE_API_TOKEN", "CLOUDFLARE_TURNSTILE_SITE_KEY",
    "CLOUDFLARE_TURNSTILE_SECRET_KEY", "FREELLMAPI_API_KEY", "VIRUSTOTAL_API_KEY",
    "URLHAUS_AUTH_KEY", "ABUSEIPDB_API_KEY", "METADEFENDER_API_KEY", "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY",
)
os.environ.update({name: "" for name in _SECRET_ENV_VARS})
os.environ.update(
    APP_ENV="test",
    DATA_DIR=str(_TEST_ROOT / "data"),
    DATABASE_URL=f"sqlite:///{(_TEST_ROOT / 'aegis_test.db').as_posix()}",
    ALLOWED_ORIGINS='["http://testserver"]',
    AI_FALLBACK_CHAIN="",
    ENABLE_VIRUSTOTAL="false",
    ENABLE_URLHAUS="false",
    ENABLE_ABUSEIPDB="false",
    FREELLMAPI_ENABLED="false",
    R2_ENABLED="false",
    AI_GATEWAY_ENABLED="false",
)

# Ensure both backend and root (scanner/) are importable under both path styles
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest


# ---------------------------------------------------------------------------
# Disable Rate Limits
# ---------------------------------------------------------------------------
# SlowAPI rate limits carry over between tests in a single pytest run and
# can easily exhaust limits (e.g. 10/min upload limits) when tests are
# executed rapidly. We globally disable rate limiting for tests.

@pytest.fixture(autouse=True, scope="session")
def disable_rate_limits():
    """Globally disable the SlowAPI limiter during test execution."""
    # Attempt to import limiter directly
    try:
        from limiter import limiter
        limiter.enabled = False
    except ImportError:
        pass
    try:
        from limiter import limiter
        limiter.enabled = False
    except ImportError:
        pass


# ---------------------------------------------------------------------------
# Database reset
# ---------------------------------------------------------------------------
# Some test files define their own `fresh_db` fixture; others (test_api.py)
# use a module-scoped client and never drop the DB between tests, which
# causes OperationalError if the on-disk DB schema is stale.
# This autouse fixture recreates tables before every test.

@pytest.fixture(autouse=True)
def fresh_db_global():
    try:
        from database import Base, create_all_tables, engine
        Base.metadata.drop_all(bind=engine)
        create_all_tables()
    except Exception:  # noqa: BLE001
        pass
    yield
    try:
        from database import Base, engine
        Base.metadata.drop_all(bind=engine)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Disable Turnstile for TestClient
# ---------------------------------------------------------------------------
# If the developer's local .env contains a real CLOUDFLARE_TURNSTILE_SECRET_KEY,
# Turnstile enforcement is activated. The TestClient sends no tokens and fails
# with 403. We patch the verification strictly inside tests to allow execution.

@pytest.fixture(autouse=True)
def mock_turnstile(monkeypatch):
    """Bypass Cloudflare Turnstile verification strictly for tests."""
    from unittest.mock import AsyncMock
    monkeypatch.setattr(
        "routers.datasets.verify_turnstile_token",
        AsyncMock(return_value=True)
    )


@pytest.fixture(autouse=True)
def enable_mock_av(monkeypatch):
    try:
        from config import settings
        monkeypatch.setattr(settings, "clamav_mock_mode", True)
    except ImportError:
        pass



