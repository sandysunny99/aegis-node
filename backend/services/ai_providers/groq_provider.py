"""
Aegis Node — Groq Cloud AI Provider.
Uses the Groq REST API (free tier) with Llama 3.1 models.
Groq is significantly faster than Gemini for inference.

Free tier: https://console.groq.com/
"""

import json
import logging

import httpx

logger = logging.getLogger(__name__)


def call_groq(
    system_prompt: str,
    user_prompt: str,
    api_key: str,
    model: str = "llama-3.1-8b-instant",
    timeout: int = 20,
) -> str | None:
    """
    Call Groq Cloud API and return the raw text response.
    Returns None on error.
    """
    from config import settings

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    if settings.ai_gateway_enabled and settings.cloudflare_ai_gateway_url:
        # e.g. https://gateway.ai.cloudflare.com/v1/{account}/{gateway}/groq/chat/completions
        base_url = settings.cloudflare_ai_gateway_url.rstrip('/')
        url = f"{base_url}/groq/chat/completions"
        headers["cf-aig-collect-log-payload"] = "true" if settings.cloudflare_ai_gateway_log_payload else "false"
        logger.info("Routing Groq request through Cloudflare AI Gateway")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
        "response_format": {"type": "json_object"},
    }

    with httpx.Client(timeout=timeout) as client:
        resp = client.post(url, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        text = data["choices"][0]["message"]["content"]
        logger.info("Groq API call successful — model=%s tokens=%s",
                    model, data.get("usage", {}).get("total_tokens", "?"))
        return text
