import sys
import asyncio
from typing import Dict, Any
import time

def setup_env():
    import os
    from dotenv import load_dotenv
    load_dotenv(override=True)

setup_env()

from config import settings
from services.llm_service import _call_provider

async def main():
    print("Provider        | Status     | Model                               | Latency   ")
    print("-" * 75)
    
    providers = ['groq', 'nvidia', 'huggingface', 'cloudflare']
    
    # Payload
    system_prompt = "You are a security analyzer. Output strictly valid JSON."
    user_prompt = 'Analyze this metadata and return JSON matching: {"verdict": "CLEAN", "severity": "NONE", "confidence": 0.99, "summary": "Test", "evidence": [], "recommendations": [], "limitations": []}'
    
    for provider in providers:
        start_time = time.time()
        try:
            # We call the internal _call_provider logic directly
            result = _call_provider(provider, False, system_prompt, user_prompt)
            latency = time.time() - start_time
            
            if result.status == "completed":
                print(f"{provider:<15} | SUCCESS    | {result.model_name:<35} | {latency:.2f}s     ")
            else:
                print(f"{provider:<15} | FAILED     | {result.status:<35} | {latency:.2f}s     ")
        except Exception as e:
            latency = time.time() - start_time
            err_msg = str(e)
            if "key" in err_msg.lower() or "not configured" in err_msg.lower():
                print(f"{provider:<15} | SKIPPED    | No key configured                   | -")
            else:
                print(f"{provider:<15} | ERROR      | {err_msg[:35]:<35} | {latency:.2f}s     ")
                print(f"  Traceback:")
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
