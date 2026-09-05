"""
Aegis Node — Safe Bounded Multi-Encoding Normalization Pipeline.
Inspired by techniques from Prompt Shield and Prompt Armor.

Features:
- Recursive URL decoding, HTML entity unescaping, and Unicode escape decoding.
- Safe Base64 and Hex candidate identification and decoding.
- Unicode homoglyph and zero-width character stripping.
- Strict resource boundaries: max recursion depth = 3, max length = 10,000 chars.
- Preserves original representation while extracting normalized payload for scanning.
"""

import base64
import html
import re
import urllib.parse

# Zero-width spaces, soft hyphens, and invisible format characters
_ZERO_WIDTH_CHARS = re.compile(r"[\u200B-\u200D\uFEFF\u00AD\u2060]")

# Comprehensive homoglyph map (Cyrillic/Greek lookalikes to ASCII)
_HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y", "і": "i", "ѕ": "s", "ј": "j",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "О": "O", "Р": "P", "Т": "T", "Х": "X", "І": "I", "Ѕ": "S",
    "α": "a", "β": "b", "ο": "o", "ν": "v", "ι": "i",
})

_HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2})+")
_BASE64_PATTERN = re.compile(r"^(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")
_MAX_RECURSION_DEPTH = 3
_MAX_STRING_LENGTH = 10000


def _safe_hex_decode(text: str) -> str:
    """Decode escaped hex strings like \\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e."""
    def repl(m):
        raw_hex = m.group(0).replace("\\x", "")
        try:
            decoded = bytes.fromhex(raw_hex).decode("utf-8", errors="replace")
            # Only substitute if printable ASCII or common text
            if all(c.isprintable() or c.isspace() for c in decoded):
                return decoded
        except Exception:
            pass
        return m.group(0)

    return _HEX_ESCAPE_PATTERN.sub(repl, text)


def _safe_base64_decode(text: str) -> str:
    """Decode base64 string if it represents valid UTF-8 text."""
    s = text.strip()
    if len(s) < 8 or len(s) > 1000 or not _BASE64_PATTERN.match(s):
        return text

    try:
        raw_bytes = base64.b64decode(s, validate=True)
        decoded = raw_bytes.decode("utf-8", errors="strict")
        # Check if the result is meaningful text (mostly printable)
        printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(len(decoded), 1)
        if printable_ratio > 0.85:
            return decoded
    except Exception:
        pass
    return text


def normalize_text(text: str, max_depth: int = _MAX_RECURSION_DEPTH) -> tuple[str, list[str]]:
    """
    Recursively normalize text across multiple encoding layers.

    Returns:
        tuple[str, list[str]]: (normalized_string, list_of_transformations_applied)
    """
    if not text or not isinstance(text, str):
        return "", []

    current = text[:_MAX_STRING_LENGTH]
    transformations: list[str] = []

    # Step 1: Strip zero-width invisible characters
    cleaned = _ZERO_WIDTH_CHARS.sub("", current)
    if cleaned != current:
        transformations.append("zero_width_stripped")
        current = cleaned

    # Step 2: Normalize homoglyphs
    homo_cleaned = current.translate(_HOMOGLYPH_MAP)
    if homo_cleaned != current:
        transformations.append("homoglyphs_normalized")
        current = homo_cleaned

    # Step 3: Recursive deobfuscation loop
    for depth in range(max_depth):
        prev = current

        # URL decode
        unquoted = urllib.parse.unquote(current)
        if unquoted != current:
            transformations.append(f"url_decode_d{depth}")
            current = unquoted

        # HTML entity unescape
        unescaped = html.unescape(current)
        if unescaped != current:
            transformations.append(f"html_unescape_d{depth}")
            current = unescaped

        # Hex escape decode
        hex_decoded = _safe_hex_decode(current)
        if hex_decoded != current:
            transformations.append(f"hex_decode_d{depth}")
            current = hex_decoded

        # Base64 decode
        b64_decoded = _safe_base64_decode(current)
        if b64_decoded != current:
            transformations.append(f"base64_decode_d{depth}")
            current = b64_decoded

        # Break early if no further transformation occurred
        if current == prev:
            break

    return current, transformations
