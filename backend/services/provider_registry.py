import logging
from dataclasses import dataclass
from backend.config import settings

logger = logging.getLogger(__name__)

@dataclass
class ProviderInfo:
    provider_id: str
    display_name: str
    model_id: str
    configured: bool
    enabled: bool
    priority: int
    timeout: int
    role: str = "fallback"

def _is_configured(provider_id: str) -> bool:
    if provider_id == "groq":
        return bool(settings.groq_api_key)
    elif provider_id == "nvidia":
        return bool(settings.nvidia_api_key)
    elif provider_id == "cloudflare":
        return bool(settings.cloudflare_api_token and settings.cloudflare_account_id)
    elif provider_id == "huggingface":
        return bool(settings.hf_token)
    elif provider_id == "freellmapi":
        return bool(settings.freellmapi_enabled and settings.freellmapi_api_key)
    elif provider_id == "gemini":
        return bool(settings.gemini_api_key)
    elif provider_id == "xai":
        return bool(settings.xai_api_key)
    elif provider_id == "ollama":
        return True
    return False

def get_registry() -> dict:
    providers = []
    
    # Provider mapping
    provider_configs = [
        {"id": "groq", "name": "Groq Cloud"},
        {"id": "nvidia", "name": "NVIDIA NIM"},
        {"id": "cloudflare", "name": "Cloudflare Workers AI"},
        {"id": "huggingface", "name": "Hugging Face"},
        {"id": "freellmapi", "name": "FreeLLM API"},
        {"id": "gemini", "name": "Google Gemini"},
        {"id": "xai", "name": "xAI"},
        {"id": "ollama", "name": "Ollama (Local)"},
    ]

    fallback_chain = [p.strip().lower() for p in settings.ai_fallback_chain.split(",") if p.strip()]

    for config in provider_configs:
        pid = config["id"]
        role = "primary" if pid == settings.ai_provider else "fallback"
        
        # FreeLLMAPI has an explicit enabled flag
        if pid == "freellmapi":
            enabled = settings.freellmapi_enabled
        else:
            enabled = True

        configured = _is_configured(pid)
        
        if pid == "cloudflare":
            pid_for_model = "cloudflare_ai"
        elif pid == "huggingface":
            pid_for_model = "hf"
        else:
            pid_for_model = pid

        model_id = getattr(settings, f"{pid_for_model}_model", "default")
        
        provider = ProviderInfo(
            provider_id=pid,
            display_name=config["name"],
            model_id=model_id,
            configured=configured,
            enabled=enabled,
            priority=0,
            timeout=10,
            role=role
        )
        providers.append(provider)

    primary_provider = settings.ai_provider
    if primary_provider == "cloudflare":
        primary_model = getattr(settings, "cloudflare_ai_model", "default")
    elif primary_provider == "huggingface":
        primary_model = getattr(settings, "hf_model", "default")
    else:
        primary_model = getattr(settings, f"{primary_provider}_model", "default")

    return {
        "default_mode": "auto",
        "primary_provider": primary_provider,
        "primary_model": primary_model,
        "fallback_chain": fallback_chain,
        "providers": [
            {
                "id": p.provider_id,
                "name": p.display_name,
                "model": p.model_id,
                "configured": p.configured,
                "role": p.role
            }
            for p in providers
        ]
    }

def get_allowed_providers() -> list[str]:
    registry = get_registry()
    return [p["id"] for p in registry["providers"] if p["configured"]]

def validate_provider_selection(provider_id: str, model_id: str | None = None) -> bool:
    allowed = get_allowed_providers()
    return provider_id in allowed
