"""Deterministic text decoding and normalization before PII inspection."""

from __future__ import annotations

import unicodedata

from .errors import IngestionSourceError


def normalize_text(text: str) -> str:
    """Apply the exact owner-approved normalization sequence."""

    if text.startswith("\ufeff"):
        text = text[1:]
    normalized = unicodedata.normalize("NFC", text)
    normalized = normalized.replace("\r\n", "\n").replace("\r", "\n")
    normalized = "\n".join(line.rstrip(" \t") for line in normalized.split("\n"))
    return normalized.strip("\n")


def decode_and_normalize(original_bytes: bytes) -> str:
    """Decode strict UTF-8 and normalize without changing the byte hash."""

    try:
        decoded = original_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise IngestionSourceError from None
    normalized = normalize_text(decoded)
    if not normalized.strip():
        raise IngestionSourceError
    return normalized
