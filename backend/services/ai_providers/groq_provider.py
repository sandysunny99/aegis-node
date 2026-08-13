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
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
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

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            text = data["choices"][0]["message"]["content"]
            logger.info("Groq API call successful — model=%s tokens=%s",
                        model, data.get("usage", {}).get("total_tokens", "?"))
            return text
    except httpx.HTTPStatusError as e:
        logger.error("Groq API HTTP error: %s %s", e.response.status_code, e.response.text[:200])
        return None
    except Exception as e:  # noqa: BLE001
        logger.error("Groq API call failed: %s", e)
        return None
