"""Contract tests for the shared citation and discriminated RAG result models."""

from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from enterprise_ai_platform.rag.models import RAGResult
from enterprise_ai_platform.retrieval.models import Citation


def test_shared_citation_requires_all_provenance_and_allows_optional_label() -> None:
    citation = Citation(
        source_id="source-001",
        document_id="policy-001",
        document_version="v1",
        chunk_id="a" * 64,
    )

    assert citation.label is None
    assert set(Citation.model_json_schema()["required"]) == {
        "source_id",
        "document_id",
        "document_version",
        "chunk_id",
    }
    with pytest.raises(ValidationError):
        Citation(
            source_id="source-001",
            document_id="policy-001",
            document_version="v1",
            chunk_id="a" * 64,
            vendor_field="forbidden",
        )


def test_result_is_an_exact_discriminated_union() -> None:
    adapter = TypeAdapter(RAGResult)
    result = adapter.validate_python(
        {
            "outcome": "abstained",
            "reason": "invalid_generated_citation",
            "prompt_version": "w3-001.v1",
            "usage": None,
        },
        strict=True,
    )

    assert result.outcome == "abstained"
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "outcome": "abstained",
                "reason": "provider_unavailable",
                "prompt_version": "w3-001.v1",
                "usage": None,
            },
            strict=True,
        )
    with pytest.raises(ValidationError):
        adapter.validate_python(
            {
                "outcome": "abstained",
                "reason": "insufficient_evidence",
                "prompt_version": "w3-001.v1",
                "usage": None,
                "raw_provider_response": {},
            },
            strict=True,
        )


@pytest.mark.parametrize(
    "prompt_version",
    ["w10-003.extractive.v1", "w10-003.extractive.v2"],
)
def test_result_accepts_versioned_w10_extractive_prompts(prompt_version: str) -> None:
    result = TypeAdapter(RAGResult).validate_python(
        {
            "outcome": "abstained",
            "reason": "insufficient_evidence",
            "prompt_version": prompt_version,
            "usage": None,
        },
        strict=True,
    )

    assert result.prompt_version == prompt_version
