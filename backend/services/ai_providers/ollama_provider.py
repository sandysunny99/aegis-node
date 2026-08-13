"""
Aegis Node — Ollama Local AI Provider.
Calls a locally running Ollama instance (100% free, no API key needed).

Install Ollama: https://ollama.com
Pull model:     ollama pull llama3.1
Run server:     ollama serve (auto-starts on install)
"""

import json
import logging

import httpx

logger = logging.getLogger(__name__)


def call_ollama(
    system_prompt: str,
    user_prompt: str,
    base_url: str = "http://localhost:11434",
    model: str = "llama3.1",
    timeout: int = 60,
) -> str | None:
    """
    Call local Ollama API and return the raw text response.
    Returns None on error or if Ollama is not running.
    """
    # First check if Ollama is reachable
    try:
        with httpx.Client(timeout=5) as check_client:
            check_client.get(f"{base_url}/api/tags")
    except Exception:
        logger.warning("Ollama is not reachable at %s — skipping local AI.", base_url)
        return None

    url = f"{base_url}/api/chat"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "format": "json",
        "options": {
            "temperature": 0.2,
            "num_predict": 1024,
        },
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            text = data.get("message", {}).get("content", "")
            logger.info("Ollama call successful — model=%s", model)
            return text
    except httpx.HTTPStatusError as e:
        logger.error("Ollama HTTP error: %s %s", e.response.status_code, e.response.text[:200])
        return None
    except Exception as e:  # noqa: BLE001
        logger.error("Ollama call failed: %s", e)
        return None
