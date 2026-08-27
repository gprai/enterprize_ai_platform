"""Unit tests for deterministic input policy and the disabled adapter."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.guardrails import (
    ALLOWED_RAG_CONTENT_TYPE,
    MAX_RAG_INPUT_CHARACTERS,
    DisabledGuardrailAdapter,
    GuardrailAssessment,
    GuardrailInputError,
    validate_rag_input,
)
from enterprise_ai_platform.retrieval.models import Query


def test_exact_input_boundaries_return_strict_queries() -> None:
    single = validate_rag_input("x", content_type=ALLOWED_RAG_CONTENT_TYPE)
    maximum = validate_rag_input(
        "x" * MAX_RAG_INPUT_CHARACTERS,
        content_type=ALLOWED_RAG_CONTENT_TYPE,
    )

    assert single == Query(text="x")
    assert len(maximum.text) == 10_000
    with pytest.raises(ValidationError):
        maximum.text = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    ("query", "content_type"),
    [
        ("", "text/plain"),
        (" \t\r\n ", "text/plain"),
        ("x" * 10_001, "text/plain"),
        ("valid", "text/markdown"),
        ("valid", "TEXT/PLAIN"),
        ("valid", object()),
        (object(), "text/plain"),
    ],
)
def test_invalid_inputs_raise_only_the_content_free_error(
    query: object,
    content_type: object,
) -> None:
    with pytest.raises(GuardrailInputError) as raised:
        validate_rag_input(  # type: ignore[arg-type]
            query,
            content_type=content_type,
        )

    assert raised.value.code == "guardrail_input_invalid"
    assert str(raised.value) == "The RAG input is invalid."
    assert raised.value.args == ("The RAG input is invalid.",)


def test_existing_query_fields_and_whitespace_normalization_are_preserved() -> None:
    existing = Query(text="  governed question  ", top_k=7, min_score=0.25)

    validated = validate_rag_input(existing, content_type="text/plain")
    raw = validate_rag_input("  governed question  ", content_type="text/plain")

    assert validated == existing
    assert validated.model_dump(mode="python") == {
        "text": "governed question",
        "top_k": 7,
        "min_score": 0.25,
    }
    assert raw == Query(text="governed question")


def test_runtime_invalid_constructed_query_is_rejected_without_exposure() -> None:
    malformed = Query.model_construct(text=object(), top_k=5, min_score=0.5)

    with pytest.raises(GuardrailInputError) as raised:
        validate_rag_input(malformed, content_type="text/plain")

    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


def test_assessment_is_strict_immutable_and_content_free() -> None:
    assessment = GuardrailAssessment(enabled=False, blocked=False)

    assert assessment.model_dump() == {"enabled": False, "blocked": False}
    assert not any(
        name in type(assessment).model_fields
        for name in ("content", "prompt", "evidence", "output", "citation")
    )
    with pytest.raises(ValidationError):
        GuardrailAssessment.model_validate(
            {"enabled": False, "blocked": False, "content": "forbidden"},
            strict=True,
        )
    with pytest.raises(ValidationError):
        GuardrailAssessment(enabled=False, blocked=True)
    with pytest.raises(ValidationError):
        GuardrailAssessment.model_validate({"enabled": 0, "blocked": 0}, strict=True)


def test_disabled_adapter_is_stateless_and_performs_no_external_activity() -> None:
    adapter = DisabledGuardrailAdapter()
    sentinel = "SECRET_W3_003_DO_NOT_LOG"

    assessment = asyncio.run(adapter.assess(sentinel))

    assert assessment == GuardrailAssessment(enabled=False, blocked=False)
    assert not hasattr(adapter, "__dict__")
    assert not hasattr(adapter, "requests")
