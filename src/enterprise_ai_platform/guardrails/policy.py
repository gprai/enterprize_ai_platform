"""Deterministic validation at the provider-neutral RAG input boundary."""

from __future__ import annotations

from typing import Final

from pydantic import ValidationError

from enterprise_ai_platform.guardrails.errors import GuardrailInputError
from enterprise_ai_platform.retrieval.models import Query

ALLOWED_RAG_CONTENT_TYPE: Final[str] = "text/plain"
MAX_RAG_INPUT_CHARACTERS: Final[int] = 10_000


def validate_rag_input(
    query: Query | str,
    *,
    content_type: str,
) -> Query:
    """Return a strict query or raise one content-free input error."""

    if not isinstance(content_type, str) or content_type != ALLOWED_RAG_CONTENT_TYPE:
        raise GuardrailInputError

    if isinstance(query, Query):
        try:
            validated = Query(
                text=query.text,
                top_k=query.top_k,
                min_score=query.min_score,
            )
        except (AttributeError, TypeError, ValidationError):
            validated = None
        if validated is None:
            raise GuardrailInputError
        if len(validated.text) > MAX_RAG_INPUT_CHARACTERS:
            raise GuardrailInputError
        return validated

    if not isinstance(query, str):
        raise GuardrailInputError
    if not query.strip() or len(query) > MAX_RAG_INPUT_CHARACTERS:
        raise GuardrailInputError
    try:
        validated = Query(text=query)
    except (TypeError, ValidationError):
        validated = None
    if validated is None:
        raise GuardrailInputError
    return validated
