"""
Aegis Node — Cloudflare Turnstile Verification Utility.
Validates client Turnstile tokens against Cloudflare's siteverify API.

Documentation: https://developers.cloudflare.com/turnstile/get-started/server-side-validation/
Endpoint: https://challenges.cloudflare.com/turnstile/v0/siteverify
"""

import logging
import httpx
from config import settings

logger = logging.getLogger(__name__)

_TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


async def verify_turnstile_token(token: str | None, remote_ip: str | None = None) -> bool:
    """
    Verify a Cloudflare Turnstile token from the client.

    Returns:
        True if verification succeeds, or if Turnstile is NOT configured (graceful bypass).
        False if Turnstile is configured and token is missing or rejected.
    """
    secret_key = (settings.cloudflare_turnstile_secret_key or "").strip()

    # If Turnstile secret key is not configured, gracefully bypass check (open in dev/tests)
    if not secret_key:
        return True

    if not token or not token.strip():
        logger.warning("Turnstile token missing while CLOUDFLARE_TURNSTILE_SECRET_KEY is enabled")
        return False

    payload = {
        "secret": secret_key,
        "response": token.strip(),
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(_TURNSTILE_SITEVERIFY_URL, data=payload)
            resp.raise_for_status()
            data = resp.json()

            success = bool(data.get("success", False))
            if not success:
                error_codes = data.get("error-codes", [])
                logger.warning("Cloudflare Turnstile token verification failed: %s", error_codes)
            return success
    except Exception as exc:  # noqa: BLE001
        logger.error("Error communicating with Cloudflare Turnstile siteverify: %s", exc)
        # On upstream verification network failure, fail closed in production if secret is set
        return False
