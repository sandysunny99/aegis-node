"""
Aegis Node — Application Settings
Loaded once at startup via pydantic-settings.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All settings are read from the .env file or environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ─── Application ─────────────────────────────────────────────────────────
    app_env: str = "development"
    app_host: str = "0.0.0.0"
    app_port: int = 8000
    secret_key: str = "change-me-before-production"

    # ─── AI Provider ─────────────────────────────────────────────────────────
    # Select active AI provider: gemini | groq | ollama | none
    ai_provider: str = "gemini"

    # ─── LLM (Google Gemini) ──────────────────────────────────────────────────
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    gemini_timeout_seconds: int = 30

    # ─── LLM (Groq Cloud — free tier, ultra-fast Llama 3) ────────────────────
    groq_api_key: str = ""
    groq_model: str = "llama-3.1-8b-instant"
    groq_timeout_seconds: int = 20

    # ─── LLM (Ollama — local, 100% free) ─────────────────────────────────────
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1"
    ollama_timeout_seconds: int = 60

    # ─── Scanner ─────────────────────────────────────────────────────────────
    clamav_host: str = "localhost"
    clamav_port: int = 3310
    max_upload_size_mb: int = 500

    # ─── Database ────────────────────────────────────────────────────────────
    database_url: str = "sqlite:///./aegis_node.db"


# Singleton — import this from anywhere in the backend.
settings = Settings()
