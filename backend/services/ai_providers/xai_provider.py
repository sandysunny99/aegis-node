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
    model: str = "grok-2-latest",
    timeout: int = 30,
) -> tuple[str | None, str | None]:
    """
    Call xAI Grok API and return (raw_text, error_message).
    Tries configured model first, with automatic fallback to grok-beta/grok-2-1212/grok-2.
    """
    api_key = api_key.strip()
    if not api_key:
        return None, "XAI_API_KEY is empty"

    url = f"{_XAI_BASE_URL}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    # Model candidates in order of preference
    models_to_try = [model] if model else []
    for candidate in ("grok-2-latest", "grok-beta", "grok-2-1212", "grok-2"):
        if candidate not in models_to_try:
            models_to_try.append(candidate)

    last_error_msg: str | None = None

    with httpx.Client(timeout=timeout) as client:
        for m in models_to_try:
            # Try with and without json_object response format
            payload = {
                "model": m,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 1024,
                "response_format": {"type": "json_object"},
            }
            try:
                resp = client.post(url, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
                text = data["choices"][0]["message"]["content"]
                logger.info(
                    "xAI Grok API call successful — model=%s tokens=%s",
                    m,
                    data.get("usage", {}).get("total_tokens", "?"),
                )
                return text, None
            except httpx.HTTPStatusError as e:
                status_code = e.response.status_code
                err_body = e.response.text[:250]
                last_error_msg = f"xAI returned HTTP {status_code}: {err_body}"
                logger.warning(
                    "xAI API HTTP error with model %s: status=%s body=%s",
                    m,
                    status_code,
                    err_body,
                )
                if status_code in (401, 403):
                    last_error_msg = f"xAI authentication error (HTTP {status_code}) — check XAI_API_KEY validity at console.x.ai"
                    break
                if status_code == 429:
                    last_error_msg = f"xAI rate limit / quota exceeded (HTTP 429) — check credits at console.x.ai"
            except Exception as e:  # noqa: BLE001
                last_error_msg = f"xAI connection error: {e}"
                logger.warning("xAI API call error with model %s: %s", m, e)

    return None, last_error_msg
