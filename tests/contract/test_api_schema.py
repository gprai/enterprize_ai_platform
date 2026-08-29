"""Machine-readable schema guarantees for the W4-001 HTTP boundary."""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import TypeAdapter, ValidationError

from enterprise_ai_platform.api.models import (
    AbstainedQueryResponse,
    AnsweredQueryResponse,
    APIErrorDetail,
    APIErrorResponse,
    LivenessResponse,
    QueryRequest,
    QueryResponse,
    ReadinessResponse,
)
from enterprise_ai_platform.llm.models import Usage
from enterprise_ai_platform.retrieval.models import Citation

REQUEST_ID = UUID("12345678-1234-4678-9234-567812345678")


@pytest.mark.parametrize(
    "model",
    [
        QueryRequest,
        LivenessResponse,
        ReadinessResponse,
        AnsweredQueryResponse,
        AbstainedQueryResponse,
        APIErrorDetail,
        APIErrorResponse,
    ],
)
def test_every_api_model_is_strict_and_extra_forbidden(model: type[object]) -> None:
    schema = model.model_json_schema()  # type: ignore[attr-defined]

    assert schema["additionalProperties"] is False


def test_query_transport_contains_only_untrusted_query_text() -> None:
    schema = QueryRequest.model_json_schema()

    assert set(schema["properties"]) == {"query"}
    assert schema["required"] == ["query"]
    assert QueryRequest.model_validate({"query": "exact text"}, strict=True).query == (
        "exact text"
    )
    with pytest.raises(ValidationError):
        QueryRequest.model_validate(
            {"query": "text", "tenant_id": "tenant-a"},
            strict=True,
        )
    with pytest.raises(ValidationError):
        QueryRequest.model_validate({"query": 1}, strict=True)


def test_answer_schema_reuses_exact_citation_and_usage_contracts() -> None:
    citation = Citation(
        source_id="source-001",
        document_id="policy-001",
        document_version="v1",
        chunk_id="a" * 64,
    )
    usage = Usage(input_tokens=2, output_tokens=1, total_tokens=3)
    response = AnsweredQueryResponse(
        request_id=REQUEST_ID,
        answer="Approved answer.",
        citations=(citation,),
        prompt_version="w3-001.v1",
        usage=usage,
    )

    assert response.citations == (citation,)
    assert isinstance(response.citations[0], Citation)
    assert isinstance(response.usage, Usage)
    assert response.model_dump(mode="json") == {
        "request_id": str(REQUEST_ID),
        "outcome": "answered",
        "answer": "Approved answer.",
        "citations": [
            {
                "source_id": "source-001",
                "document_id": "policy-001",
                "document_version": "v1",
                "chunk_id": "a" * 64,
                "label": None,
            }
        ],
        "prompt_version": "w3-001.v1",
        "usage": {
            "input_tokens": 2,
            "output_tokens": 1,
            "total_tokens": 3,
            "estimated_cost_usd": None,
        },
    }


def test_answered_usage_is_explicitly_null_when_trusted_result_has_none() -> None:
    response = AnsweredQueryResponse(
        request_id=REQUEST_ID,
        answer="Approved answer.",
        citations=(
            Citation(
                source_id="source-001",
                document_id="policy-001",
                document_version="v1",
                chunk_id="a" * 64,
            ),
        ),
        prompt_version="w3-001.v1",
        usage=None,
    )

    assert response.model_dump(mode="json")["usage"] is None


def test_abstention_schema_has_no_answer_citation_or_usage_field() -> None:
    response = AbstainedQueryResponse(
        request_id=REQUEST_ID,
        reason="no_authorized_evidence",
        prompt_version="w3-001.v1",
    )

    assert response.model_dump(mode="json") == {
        "request_id": str(REQUEST_ID),
        "outcome": "abstained",
        "reason": "no_authorized_evidence",
        "prompt_version": "w3-001.v1",
    }
    assert set(AbstainedQueryResponse.model_json_schema()["properties"]) == {
        "request_id",
        "outcome",
        "reason",
        "prompt_version",
    }


def test_query_response_is_an_exact_discriminated_union() -> None:
    adapter = TypeAdapter(QueryResponse)

    result = adapter.validate_python(
        {
            "request_id": REQUEST_ID,
            "outcome": "abstained",
            "reason": "insufficient_evidence",
            "prompt_version": "w3-001.v1",
        },
        strict=True,
    )

    assert isinstance(result, AbstainedQueryResponse)
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "request_id": REQUEST_ID,
                "outcome": "abstained",
                "reason": "provider_unavailable",
                "prompt_version": "w3-001.v1",
            },
            strict=True,
        )


def test_error_schema_omits_retryable_when_policy_does_not_define_it() -> None:
    response = APIErrorResponse(
        request_id=REQUEST_ID,
        error=APIErrorDetail(code="internal_error", message="Safe message."),
    )

    assert response.model_dump(mode="json", exclude_none=True) == {
        "request_id": str(REQUEST_ID),
        "error": {"code": "internal_error", "message": "Safe message."},
    }
    assert "status" not in APIErrorResponse.model_json_schema()["properties"]


def test_public_schemas_expose_no_internal_or_reasoning_fields() -> None:
    models = (
        QueryRequest,
        AnsweredQueryResponse,
        AbstainedQueryResponse,
        APIErrorResponse,
    )
    schemas = " ".join(
        str(model.model_json_schema()).casefold()
        for model in models
    )
    forbidden = (
        "chain_of_thought",
        "internal_endpoint",
        "model_version",
        "provider_response",
        "retriever_version",
        "system_prompt",
    )

    assert all(
        "evidence" not in model.model_json_schema()["properties"]
        for model in models
    )
    assert not any(field in schemas for field in forbidden)