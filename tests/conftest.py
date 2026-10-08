"""Aegis Node Test Suite â€” conftest.py

Shared fixtures that apply to ALL test files.
"""
import os
import sys
from pathlib import Path

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



