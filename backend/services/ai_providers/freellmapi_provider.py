import httpx

def call_freellmapi(
    system_prompt: str,
    user_prompt: str,
    base_url: str,
    api_key: str,
    model: str,
    timeout: int,
) -> tuple[str | None, str | None]:
    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
        "stream": False
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=headers, json=payload)
            resp.raise_for_status()
            data = resp.json()
            content = data.get("choices", [{}])[0].get("message", {}).get("content")
            if not content:
                return None, "FreeLLMAPI returned empty or missing content"
            return content, None
    except httpx.HTTPError as exc:
        err_msg = str(exc)
        if hasattr(exc, "response") and exc.response is not None:
            err_msg += f" - {exc.response.text}"
        return None, err_msg
    except Exception as exc:
        return None, str(exc)
