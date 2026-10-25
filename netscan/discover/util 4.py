"""Text cleaning for strings that arrive from devices on the network."""

from __future__ import annotations

import re

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def clean(value, limit: int = 120) -> str:
    """Printable, single-line, length-capped text. Bytes are decoded leniently."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", "replace")
    text = _CONTROL.sub(" ", str(value))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit]
