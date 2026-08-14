"""
Aegis Node — xAI / Grok AI Provider.
Uses the xAI REST API (OpenAI-compatible) with Grok models.

xAI API is OpenAI-compatible — same endpoint shape, different base URL and model names.
API reference: https://docs.x.ai/api
Free tier / dashboard: https://console.x.ai/
"""

import logging

import httpx

logger = logging.getLogger(__name__)

_XAI_BASE_URL = "https://api.x.ai/v1"


def call_xai(
    system_prompt: str,
    user_prompt: str,
    api_key: str,
    model: str = "grok-3-mini",
    timeout: int = 30,
) -> str | None:
    """
    Call xAI Grok API and return the raw text response.
    Returns None on error.
    """
    url = f"{_XAI_BASE_URL}/chat/completions"
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
            logger.info(
                "xAI Grok API call successful — model=%s tokens=%s",
                model,
                data.get("usage", {}).get("total_tokens", "?"),
            )
            return text
    except httpx.HTTPStatusError as e:
        logger.error(
            "xAI API HTTP error: %s %s",
            e.response.status_code,
            e.response.text[:200],
        )
        return None
    except Exception as e:  # noqa: BLE001
        logger.error("xAI API call failed: %s", e)
        return None
