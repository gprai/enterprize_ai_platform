"""Unit coverage for immutable W3-004 RAG identity descriptors."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.json_contracts import strict_json_loads
from enterprise_ai_platform.rag_rollback.identity import (
    canonical_json_bytes,
    identity_sha256,
    validate_identity_pair,
)
from enterprise_ai_platform.rag_rollback.models import RAGIdentityDescriptor


def test_identity_pair_is_strict_transitive_and_changes_only_approved_fields() -> None:
    known_good, regression = validate_identity_pair()

    assert known_good.identity_alias == "known-good"
    assert regression.identity_alias == "synthetic-regression"
    assert known_good.provider.profile == "w3-002.controlled-fake.v1"
    assert regression.provider.profile == (
        "w3-004.synthetic-invalid-citation-q1-q2.v1"
    )
    assert known_good.baseline == regression.baseline
    assert known_good.repository == regression.repository
    assert known_good.prompt == regression.prompt
    assert known_good.rag_configuration == regression.rag_configuration
    assert known_good.retriever == regression.retriever
    assert known_good.evidence == regression.evidence
    assert known_good.evaluation == regression.evaluation
    assert known_good.guardrail == regression.guardrail
    assert identity_sha256(known_good) != identity_sha256(regression)


def test_canonical_identity_hash_is_independent_of_object_field_order() -> None:
    left = {"b": [2, 1], "a": {"d": False, "c": None}}
    right = {"a": {"c": None, "d": False}, "b": [2, 1]}

    assert canonical_json_bytes(left) == canonical_json_bytes(right)
    assert canonical_json_bytes(left).endswith(b"\n")


def test_descriptor_rejects_unknown_missing_and_duplicate_fields() -> None:
    known_good, _ = validate_identity_pair()
    payload = known_good.model_dump(mode="json")

    with pytest.raises(ValidationError):
        RAGIdentityDescriptor.model_validate(
            {**payload, "unapproved": True},
            strict=True,
        )
    missing = dict(payload)
    missing.pop("baseline")
    with pytest.raises(ValidationError):
        RAGIdentityDescriptor.model_validate(missing, strict=True)
    with pytest.raises(ValueError):
        strict_json_loads(
            '{"schema_version":"w3-004.rag-identity.v1",'
            '"schema_version":"w3-004.rag-identity.v1"}'
        )


def test_descriptor_serialization_contains_no_runtime_or_evidence_content() -> None:
    known_good, regression = validate_identity_pair()
    serialized = json.dumps(
        [
            known_good.model_dump(mode="json"),
            regression.model_dump(mode="json"),
        ],
        sort_keys=True,
    )

    for forbidden in (
        "question",
        "answer_text",
        "prompt_content",
        "provider_response",
        "credential",
        "tenant_data",
    ):
        assert forbidden not in serialized
