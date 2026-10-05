import sys
from backend.config import settings
from backend.services.ai_providers.nvidia_provider import call_nvidia
from backend.services.ai_providers.huggingface_provider import call_huggingface
from backend.services.ai_providers.cloudflare_provider import call_cloudflare

system_prompt = 'You are a security analyzer. Output strictly valid JSON.'
user_prompt = 'Analyze this metadata and return JSON matching: {"verdict": "CLEAN", "severity": "NONE", "confidence": 0.99, "summary": "Test", "evidence": [], "recommendations": [], "limitations": []}'

print('NVIDIA:', call_nvidia(system_prompt, user_prompt, settings.nvidia_api_key, settings.nvidia_model, settings.nvidia_timeout_seconds))
print('HF:', call_huggingface(system_prompt, user_prompt, settings.fallback_hf_token, settings.hf_model, settings.hf_timeout_seconds))
print('Cloudflare:', call_cloudflare(system_prompt, user_prompt, settings.fallback_cloudflare_api_token, settings.cloudflare_account_id, settings.cloudflare_ai_model, settings.cloudflare_timeout_seconds))
