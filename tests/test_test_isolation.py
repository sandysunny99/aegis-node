"""Guards for R11: the suite must never write into the repository's data/ folder
or run with real provider credentials from the developer's .env."""

from pathlib import Path

from config import settings

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_data_dir_is_outside_repository():
    data_dir = Path(settings.data_dir).resolve()
    assert not data_dir.is_relative_to(REPO_ROOT)


def test_database_is_outside_repository():
    assert settings.database_url.startswith("sqlite:///")
    db_path = Path(settings.database_url.removeprefix("sqlite:///")).resolve()
    assert not db_path.is_relative_to(REPO_ROOT)


def test_file_service_uses_isolated_dirs():
    from services import file_service

    assert not file_service._SAMPLES_DIR.resolve().is_relative_to(REPO_ROOT)


def test_provider_credentials_are_blank():
    for name in (
        "api_key", "groq_api_key", "nvidia_api_key", "hf_token", "cloudflare_api_token",
        "cloudflare_turnstile_secret_key", "gemini_api_key", "xai_api_key",
    ):
        assert not getattr(settings, name), f"{name} leaked into the test environment"
    assert settings.app_env == "test"
