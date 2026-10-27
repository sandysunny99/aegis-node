"""
Remove credentials from text that may be shown to users, stored or logged (provider
error messages often echo request headers). Replaces configured secret values and
common token shapes with "[redacted]".
"""

import re

from config import settings

_TOKEN_SHAPES = re.compile(
    r"(?i)(bearer\s+)[^\s'\"]+"                 # Authorization: Bearer <token>
    r"|\b(?:nvapi-|gsk_|xai-|hf_|sk-|AIza)[A-Za-z0-9_\-]{8,}"  # NVIDIA, Groq, xAI, HF, OpenAI-style, Google
)


def _secret_values() -> list[str]:
    values = []
    for name in type(settings).model_fields:
        if name.endswith(("_key", "_token", "_secret", "_secret_key")):
            value = getattr(settings, name, None)
            if isinstance(value, str) and len(value.strip()) >= 8:
                values.append(value.strip())
    return sorted(values, key=len, reverse=True)


def redact_secrets(text: str | None) -> str | None:
    if not text:
        return text
    out = str(text)
    for value in _secret_values():
        out = out.replace(value, "[redacted]")
    return _TOKEN_SHAPES.sub(lambda m: (m.group(1) or "") + "[redacted]", out)
