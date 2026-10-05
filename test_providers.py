import asyncio
import time
from backend.config import settings
from backend.services.llm_service import _call_groq, _call_nvidia, _call_huggingface, _call_cloudflare

system_prompt = 'You are a security analyzer. Output strictly valid JSON.'
user_prompt = 'Analyze this metadata and return JSON matching: {"verdict": "CLEAN", "severity": "NONE", "confidence": 0.99, "summary": "Test", "evidence": [], "recommendations": [], "limitations": []}'

def test_provider(name, func):
    start = time.time()
    try:
        if name in ['nvidia', 'huggingface', 'cloudflare']:
            if name == 'nvidia':
                res = func(system_prompt, user_prompt, api_key=settings.nvidia_api_key)
            elif name == 'huggingface':
                res = func(system_prompt, user_prompt, api_key=settings.fallback_hf_token)
            elif name == 'cloudflare':
                res = func(system_prompt, user_prompt, api_token=settings.fallback_cloudflare_api_token, account_id=settings.cloudflare_account_id)
        else:
            res = func(system_prompt, user_prompt)
            
        print(f'{name} -> {res.status} ({res.model_name}): {res.summary} in {time.time() - start:.2f}s')
    except Exception as e:
        print(f'{name} -> ERROR: {e} in {time.time() - start:.2f}s')
        import traceback
        traceback.print_exc()

print("Starting tests...")
test_provider('nvidia', _call_nvidia)
test_provider('huggingface', _call_huggingface)
test_provider('cloudflare', _call_cloudflare)
