"""Contract tests for the public W3-003 guardrail boundary."""

from __future__ import annotations

import inspect
from typing import get_args

import pytest
from pydantic import ValidationError

import enterprise_ai_platform.guardrails as guardrails
from enterprise_ai_platform.guardrails import (
    DisabledGuardrailAdapter,
    GuardrailAdapter,
    GuardrailAssessment,
    GuardrailInputError,
    validate_rag_input,
)
from enterprise_ai_platform.rag.models import AbstentionReason
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.models import Query


def test_public_exports_are_exact_and_intentional() -> None:
    assert guardrails.__all__ == [
        "ALLOWED_RAG_CONTENT_TYPE",
        "MAX_RAG_INPUT_CHARACTERS",
        "DisabledGuardrailAdapter",
        "GuardrailAdapter",
        "GuardrailAssessment",
        "GuardrailInputError",
        "validate_rag_input",
    ]


def test_rag_and_validator_signatures_preserve_query_compatibility() -> None:
    answer_parameters = list(inspect.signature(RAGService.answer).parameters.values())
    validator_parameters = list(inspect.signature(validate_rag_input).parameters.values())

    assert [item.name for item in answer_parameters] == [
        "self",
        "auth_context",
        "query",
        "content_type",
    ]
    assert answer_parameters[-1].kind is inspect.Parameter.KEYWORD_ONLY
    assert answer_parameters[-1].default == "text/plain"
    assert [item.name for item in validator_parameters] == ["query", "content_type"]
    assert validator_parameters[-1].kind is inspect.Parameter.KEYWORD_ONLY
    assert validator_parameters[-1].default is inspect.Parameter.empty
    assert validate_rag_input(Query(text="existing"), content_type="text/plain") == Query(
        text="existing"
    )


def test_input_error_has_one_safe_code_and_no_input_fields() -> None:
    error = GuardrailInputError()

    assert error.code == "guardrail_input_invalid"
    assert vars(error) == {}
    assert "query" not in str(error).casefold()
    assert "content" not in str(error).casefold()


def test_assessment_schema_is_strict_content_free_and_closed() -> None:
    schema = GuardrailAssessment.model_json_schema()

    assert schema["additionalProperties"] is False
    assert set(schema["properties"]) == {"enabled", "blocked"}
    assert set(schema["required"]) == {"enabled", "blocked"}
    with pytest.raises(ValidationError):
        GuardrailAssessment.model_validate(
            {"enabled": False, "blocked": False, "provider_response": {}},
            strict=True,
        )


def test_disabled_adapter_satisfies_only_the_interface_contract() -> None:
    adapter = DisabledGuardrailAdapter()

    assert isinstance(adapter, GuardrailAdapter)
    public_attributes = {name for name in vars(type(adapter)) if not name.startswith("__")}
    assert public_attributes == {"assess"}


def test_existing_abstention_taxonomy_is_unchanged() -> None:
    assert get_args(AbstentionReason.__value__) == (
        "insufficient_evidence",
        "no_authorized_evidence",
        "conflicting_evidence",
        "malformed_evidence",
        "invalid_generated_citation",
    )
