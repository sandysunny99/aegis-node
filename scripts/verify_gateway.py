"""Manual check of Groq direct and via the Cloudflare AI Gateway.

This reads the real keys in the local .env and makes billable Groq calls, so it does
nothing unless run with --confirm-paid-calls. Never run it from tests, CI or an agent
without the owner asking. It prints only status, model name and error text, never keys.

Usage (from the repo root): python scripts/verify_gateway.py --confirm-paid-calls
"""

import sys
from pathlib import Path

# Run from the repo root: python scripts/<name>.py  (backend/ holds config and services)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import logging
import os

CONFIRM_FLAG = "--confirm-paid-calls"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
settings = None
_call_groq = None


def _load_backend():
    """Load .env and the backend only after the caller opted in to paid calls."""
    global settings, _call_groq
    from dotenv import load_dotenv

    load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

    from config import settings as loaded_settings
    from services.llm_service import _call_groq as loaded_call

    settings, _call_groq = loaded_settings, loaded_call


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

def main(argv: list[str]) -> int:
    if CONFIRM_FLAG not in argv:
        print("verify_gateway: this reads the local .env and makes billable Groq calls.")
        print(f"Nothing was loaded or sent. Re-run with {CONFIRM_FLAG} to proceed.")
        return 2
    _load_backend()
    test_direct_mode()
    test_gateway_mode()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

