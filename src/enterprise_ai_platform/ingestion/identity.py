"""Delimiter-safe SHA-256 identities for ingestion sources and versions."""

from __future__ import annotations

import hashlib

from .errors import IngestionSourceError


def _length_prefixed(values: tuple[object, ...]) -> bytes:
    canonical = bytearray()
    for value in values:
        if (
            not isinstance(value, str)
            or not value
            or value != value.strip()
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise IngestionSourceError
        encoded = value.encode("utf-8")
        if len(encoded) > 0xFFFFFFFF:
            raise IngestionSourceError
        canonical.extend(len(encoded).to_bytes(4, "big"))
        canonical.extend(encoded)
    return bytes(canonical)


def document_id_for(tenant_id: str, source_id: str) -> str:
    """Identify one owner-approved source within one tenant."""

    return hashlib.sha256(_length_prefixed((tenant_id, source_id))).hexdigest()


def content_hash_for(original_bytes: bytes) -> str:
    """Hash the authoritative original bytes before normalization."""

    if not isinstance(original_bytes, bytes) or not original_bytes:
        raise IngestionSourceError
    return hashlib.sha256(original_bytes).hexdigest()


def document_version_for(document_id: str, content_hash: str) -> str:
    """Identify one exact original-byte version of a document."""

    if any(
        len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
        for value in (document_id, content_hash)
    ):
        raise IngestionSourceError
    return hashlib.sha256(_length_prefixed((document_id, content_hash))).hexdigest()
