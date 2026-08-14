"""
Aegis Node — Application Settings
Loaded once at startup via pydantic-settings.
"""

import logging
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from pathlib import Path

logger = logging.getLogger("aegis.config")

_ROOT_ENV = Path(__file__).resolve().parent.parent / ".env"
_LOCAL_ENV = Path(__file__).resolve().parent / ".env"


class Settings(BaseSettings):
    """All settings are read from the .env file or environment variables."""

    model_config = SettingsConfigDict(
        env_file=(_LOCAL_ENV, _ROOT_ENV, ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ─── Application ─────────────────────────────────────────────────────────
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    secret_key: str = "change-me-before-production"
    allowed_origins: list[str] = ["*"]
    trusted_proxies: list[str] = ["127.0.0.1", "::1"]

    # ─── API Key Guard (optional) ─────────────────────────────────────────────
    # If empty (default), write endpoints are open — suitable for local dev.
    # Set to a long random string in .env to protect upload/scan/remediate routes.
    # Clients must send:  X-API-Key: <value>
    api_key: str = ""

    # ─── Download Token Expiry ────────────────────────────────────────────────
    # How long a download token is valid after remediation (in minutes).
    # Default: 60 minutes (1 hour). Set to 0 to disable expiry.
    download_token_expiry_minutes: int = 60

    # ─── Supported File Extensions ─────────────────────────────────────────────
    allowed_extensions: set[str] = {".csv", ".parquet", ".json", ".jsonl", ".xlsx", ".txt"}

    # ─── AI Provider ─────────────────────────────────────────────────────────
    # Primary AI provider: gemini | groq | ollama | none
    ai_provider: str = "gemini"

    # ─── AI Fallback Chain ────────────────────────────────────────────────────
    ai_fallback_chain: str = ""

    fallback_gemini_api_key: str = ""
    fallback_groq_api_key: str = ""
    fallback_xai_api_key: str = ""

    # ─── LLM (Google Gemini) ──────────────────────────────────────────────────
    gemini_api_key: str = ""
    gemini_model: str = "gemini-flash-latest"
    gemini_timeout_seconds: int = 30

    # ─── LLM (Groq Cloud — free tier, ultra-fast Llama 3) ────────────────────
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    groq_timeout_seconds: int = 20

    # ─── LLM (xAI / Grok — OpenAI-compatible API) ────────────────────────────
    xai_api_key: str = ""
    xai_model: str = "grok-3-mini"
    xai_timeout_seconds: int = 30

    # ─── LLM (Ollama — local, 100% free) ─────────────────────────────────────
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_timeout_seconds: int = 60

    # ─── Scanner ─────────────────────────────────────────────────────────────
    clamav_host: str = "localhost"
    clamav_port: int = 3310
    clamav_mock_mode: bool = False
    max_upload_size_mb: int = 500
    enable_heuristics: bool = True  # Set ENABLE_HEURISTICS=false to disable Stage 0.5


    # ─── Database ────────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./aegis_node.db"

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if self.app_env.lower() == "production":
            if self.secret_key == "change-me-before-production":
                raise ValueError("SECRET_KEY must be set to a secure secret in production!")
            if not self.api_key:
                logger.warning("SECURITY WARNING: API_KEY is empty in production environment. Write endpoints are unprotected.")
        elif not self.api_key and self.app_env.lower() != "development":
            logger.warning("API_KEY is not configured — write endpoints are publicly accessible.")
        return self


# Singleton — import this from anywhere in the backend.
settings = Settings()
