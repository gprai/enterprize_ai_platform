"""Deterministic token-span chunking with bounded overlap."""

from __future__ import annotations

from .errors import IngestionSourceError
from .models import CHUNK_OVERLAP_TOKENS, CHUNK_TARGET_TOKENS, TextChunk
from .tokenizer import IngestionTokenizer


def chunk_text(
    text: str,
    tokenizer: IngestionTokenizer,
    *,
    target_tokens: int = CHUNK_TARGET_TOKENS,
    overlap_tokens: int = CHUNK_OVERLAP_TOKENS,
) -> tuple[TextChunk, ...]:
    """Return stable chunks whose next window reuses the approved token overlap."""

    if target_tokens <= 0 or overlap_tokens < 0 or overlap_tokens >= target_tokens:
        raise IngestionSourceError
    spans = tokenizer.token_spans(text)
    if not spans:
        raise IngestionSourceError
    chunks: list[TextChunk] = []
    start_token = 0
    while start_token < len(spans):
        end_token = min(start_token + target_tokens, len(spans))
        start_character = spans[start_token].start
        end_character = spans[end_token - 1].end
        chunk_value = text[start_character:end_character]
        if not chunk_value.strip():
            raise IngestionSourceError
        chunks.append(
            TextChunk(
                chunk_index=len(chunks),
                text=chunk_value,
                token_count=end_token - start_token,
            )
        )
        if end_token == len(spans):
            break
        start_token = end_token - overlap_tokens
    return tuple(chunks)
