"""Unit tests for strict W2-001 provider-neutral models."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
    Answer,
    ApprovedException,
    AuthContext,
    Chunk,
    Citation,
    Classification,
    CollectionSpec,
    Document,
    IngestionStatus,
    PiiStatus,
    Query,
    Role,
    deterministic_chunk_id,
)


def normalized_vector(axis: int = 0) -> tuple[float, ...]:
    values = [0.0] * APPROVED_EMBEDDING_DIMENSION
    values[axis] = 1.0
    return tuple(values)


def metadata(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "tenant_id": "tenant-a",
        "source_id": "DOC-POLICY-001",
        "media_type": "text/markdown",
        "document_id": "policy-001",
        "document_version": "v1",
        "classification": Classification.INTERNAL,
        "allowed_roles": frozenset({Role.READER}),
        "allowed_groups": frozenset({"finance"}),
        "data_owner": "policy-team",
        "content_hash": "a" * 64,
        "pii_status": PiiStatus.CLEAR,
        "ingestion_status": IngestionStatus.INDEXED,
    }
    values.update(overrides)
    return values


def test_document_requires_identity_classification_and_access_metadata() -> None:
    document = Document(**metadata(), content="Approved synthetic policy text.")
    assert document.tenant_id == "tenant-a"
    assert document.allowed_roles == frozenset({Role.READER})

    invalid = metadata()
    del invalid["classification"]
    with pytest.raises(ValidationError):
        Document(**invalid, content="Missing classification")


def test_models_reject_unknown_and_obsolete_values() -> None:
    with pytest.raises(ValidationError):
        Document(**metadata(tenant_id="demo"), content="Obsolete tenant")
    with pytest.raises(ValidationError):
        Query(text="question", tenant_id="tenant-a")
    with pytest.raises(ValidationError):
        AuthContext(
            subject_id="reader-1",
            tenant_id="tenant-a",
            roles=frozenset({"project_owner"}),
            clearance=Classification.INTERNAL,
        )


def test_chunk_identity_is_deterministic_and_version_sensitive() -> None:
    expected = deterministic_chunk_id(
        tenant_id="tenant-a",
        document_id="policy-001",
        document_version="v1",
        content_hash="a" * 64,
        chunk_index=0,
    )
    same = deterministic_chunk_id(
        tenant_id="tenant-a",
        document_id="policy-001",
        document_version="v1",
        content_hash="a" * 64,
        chunk_index=0,
    )
    changed = deterministic_chunk_id(
        tenant_id="tenant-a",
        document_id="policy-001",
        document_version="v2",
        content_hash="a" * 64,
        chunk_index=0,
    )
    assert expected == same
    assert expected != changed

    chunk = Chunk(
        **metadata(),
        chunk_id=expected,
        chunk_index=0,
        text="Synthetic chunk",
        embedding=normalized_vector(),
    )
    assert chunk.chunk_id == expected
    with pytest.raises(ValidationError):
        Chunk.model_validate({**chunk.model_dump(), "chunk_id": "b" * 64})


def test_embedding_contract_rejects_dimension_and_normalization_mismatch() -> None:
    chunk_id = deterministic_chunk_id(
        tenant_id="tenant-a",
        document_id="policy-001",
        document_version="v1",
        content_hash="a" * 64,
        chunk_index=0,
    )
    with pytest.raises(ValidationError):
        Chunk(
            **metadata(),
            chunk_id=chunk_id,
            chunk_index=0,
            text="Bad dimension",
            embedding=(1.0,),
        )
    with pytest.raises(ValidationError):
        Chunk(
            **metadata(),
            chunk_id=chunk_id,
            chunk_index=0,
            text="Bad norm",
            embedding=tuple([0.5] + [0.0] * 383),
        )


def test_collection_spec_is_exactly_emb_001() -> None:
    assert CollectionSpec(name="enterprise_ai_w2_001").dimension == 384
    with pytest.raises(ValidationError):
        CollectionSpec(name="enterprise_ai_w2_001", dimension=768)
    with pytest.raises(ValidationError):
        CollectionSpec(name="enterprise_ai_w2_001", normalized=False)


def test_pii_exception_requires_owner_rationale_and_unexpired_time() -> None:
    now = datetime.now(UTC)
    exception = ApprovedException(
        owner="privacy-owner",
        rationale="Synthetic exception for contract validation",
        expires_at=now + timedelta(hours=1),
        document_id="policy-001",
        entity_types=frozenset({"PASSPORT_NUMBER"}),
    )
    approved = Document(
        **metadata(
            pii_status=PiiStatus.APPROVED_EXCEPTION,
            approved_exception=exception,
        ),
        content="Approved synthetic exception",
    )
    assert approved.is_indexable(now)
    assert approved.source_id == "DOC-POLICY-001"
    assert approved.media_type == "text/markdown"
    assert not approved.is_indexable(now + timedelta(hours=2))
    with pytest.raises(ValidationError):
        Document(
            **metadata(pii_status=PiiStatus.APPROVED_EXCEPTION),
            content="Missing exception detail",
        )


def test_answer_distinguishes_cited_response_from_abstention() -> None:
    citation = Citation(
        source_id="source-001",
        document_id="policy-001",
        document_version="v1",
        chunk_id="a" * 64,
        label="Policy section 1",
    )
    assert Answer(text="Cited response", citations=(citation,)).abstained is False
    assert Answer(abstained=True, abstention_reason="insufficient evidence").citations == ()
    with pytest.raises(ValidationError):
        Answer(text="Unsupported response")
