"""Aegis Node Test Suite — conftest.py

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
# Rate-limit reset
# ---------------------------------------------------------------------------
# All integration test files share one Python process and (in most cases)
# the same `main.app` instance.  SlowAPI's InMemoryStrategy accumulates
# counts across tests, so the 10/min upload limit is exhausted by the time
# later test files run.  We reset every limiter instance we can find before
# each test so each test starts with a clean slate.

def _reset_all_limiters():
    """Reset SlowAPI limiter(s) reachable via any known import path."""
    for mod_name in ("main", "backend.main"):
        try:
            import importlib
            mod = sys.modules.get(mod_name) or importlib.import_module(mod_name)
            lim = getattr(mod, "limiter", None)
            if lim is not None:
                # SlowAPI Limiter exposes reset() which clears InMemoryStrategy
                lim.reset()
        except Exception:  # noqa: BLE001
            pass

    # Also clear any Limiter instances created in router modules
    for mod_name in list(sys.modules.keys()):
        if "analysis" in mod_name or "datasets" in mod_name:
            try:
                mod = sys.modules[mod_name]
                lim = getattr(mod, "limiter", None)
                if lim is not None and hasattr(lim, "reset"):
                    lim.reset()
            except Exception:  # noqa: BLE001
                pass


@pytest.fixture(autouse=True)
def reset_rate_limits():
    _reset_all_limiters()
    yield
    _reset_all_limiters()


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
