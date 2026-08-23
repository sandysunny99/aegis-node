"""
Aegis Node — Cloudflare Workers AI Provider.
Runs open models (Llama 3.1 8B Instruct, Mistral) on Cloudflare's serverless edge.

API Reference: https://developers.cloudflare.com/workers-ai/
Authentication: Cloudflare API Token + Account ID
Free tier: Free daily neuron allocation per account.
"""

import json
import logging
import httpx

logger = logging.getLogger(__name__)

_DEFAULT_MODEL = "@cf/meta/llama-3.1-8b-instruct"


def call_cloudflare(
    system_prompt: str,
    user_prompt: str,
    api_token: str,
    account_id: str,
    model: str = _DEFAULT_MODEL,
    timeout: int = 30,
) -> tuple[str | None, str | None]:
    """
    Call Cloudflare Workers AI API and return (raw_text, error_message).
    Endpoint: https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model}
    """
    api_token = (api_token or "").strip()
    account_id = (account_id or "").strip()

    if not api_token:
        return None, "CLOUDFLARE_API_TOKEN is empty"
    if not account_id:
        return None, "CLOUDFLARE_ACCOUNT_ID is empty"

    model_name = model or _DEFAULT_MODEL
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model_name}"
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }

    # Format messages payload
    payload = {
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()

            # Cloudflare Workers AI returns {"result": {"response": "..."}, "success": true}
            if data.get("success"):
                result = data.get("result", {})
                raw_text = result.get("response") or ""
                logger.info(
                    "Cloudflare Workers AI call successful — model=%s",
                    model_name,
                )
                return raw_text, None

            errors = data.get("errors", [])
            err_msg = json.dumps(errors) if errors else "Cloudflare Workers AI returned success=false"
            return None, f"Cloudflare Workers AI error: {err_msg}"

    except httpx.HTTPStatusError as e:
        status_code = e.response.status_code
        err_body = e.response.text[:250]
        if status_code in (401, 403):
            err_msg = f"Cloudflare API authentication failed (HTTP {status_code}) — check CLOUDFLARE_API_TOKEN"
        elif status_code == 429:
            err_msg = f"Cloudflare Workers AI rate limit / neuron quota reached (HTTP 429)"
        else:
            err_msg = f"Cloudflare Workers AI returned HTTP {status_code}: {err_body}"

        logger.warning(
            "Cloudflare Workers AI HTTP error: status=%s body=%s",
            status_code,
            err_body,
        )
        return None, err_msg

    except Exception as e:  # noqa: BLE001
        logger.warning("Cloudflare Workers AI connection error: %s", e)
        return None, f"Cloudflare connection error: {e}"
