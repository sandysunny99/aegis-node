import os
import sys
import logging
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

from config import settings
from services.llm_service import _call_groq

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_direct_mode():
    print("==================================================")
    print("VERIFY DIRECT MODE")
    settings.ai_gateway_enabled = False

    try:
        # Override the model config to use the known working model
        settings.groq_model = "openai/gpt-oss-20b"
        res = _call_groq(
            system_prompt="You are a security analyst. Return valid JSON.",
            user_prompt="Analyze this: Clean file.",
        )
        print(f"direct_request = {'PASS' if res.status == 'completed' else 'FAIL'}")
        print(f"model = {res.model_name}")
        print(f"llm_status = {res.status}")
        print(f"llm_error = {res.error}")
        return True if res.status == 'completed' else False
    except Exception as e:
        print(f"direct_request = FAIL ({e})")
        return False

def test_gateway_mode():
    print("==================================================")
    print("VERIFY GATEWAY MODE")
    settings.ai_gateway_enabled = True
    settings.groq_model = "openai/gpt-oss-20b"

    if not settings.cloudflare_ai_gateway_url:
        print("gateway_request = FAIL (CLOUDFLARE_AI_GATEWAY_URL not configured)")
        return False

    try:
        res = _call_groq(
            system_prompt="You are a security analyst. Return valid JSON.",
            user_prompt="Analyze this: Clean file.",
        )
        print(f"gateway_request = {'PASS' if res.status == 'completed' else 'FAIL'}")
        print(f"provider model = {res.model_name}")
        print(f"llm_status = {res.status}")
        print(f"llm_error = {res.error}")
        return True if res.status == 'completed' else False
    except Exception as e:
        print(f"gateway_request = FAIL ({e})")
        return False

if __name__ == "__main__":
    test_direct_mode()
    test_gateway_mode()
