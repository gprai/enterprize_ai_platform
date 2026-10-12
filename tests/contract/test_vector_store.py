"""Backend-independent contract tests that always run against the fake store."""

from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.errors import (
    VectorStoreAuthorizationError,
    VectorStoreUnavailableError,
    VectorStoreValidationError,
)
from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
    AuthContext,
    Chunk,
    Classification,
    CollectionSpec,
    IngestionStatus,
    PiiStatus,
    Query,
    Role,
    deterministic_chunk_id,
)
from enterprise_ai_platform.retrieval.vector_store import VectorStore


def vector(axis: int = 0) -> tuple[float, ...]:
    values = [0.0] * APPROVED_EMBEDDING_DIMENSION
    values[axis] = 1.0
    return tuple(values)


def auth(*roles: Role, tenant_id: str = "tenant-a") -> AuthContext:
    return AuthContext(
        subject_id="contract-user",
        tenant_id=tenant_id,
        roles=frozenset(roles),
        clearance=Classification.RESTRICTED,
        groups=frozenset({"finance"}),
    )


def chunk(index: int = 0, *, version: str = "v1") -> Chunk:
    content_hash = "a" * 64
    return Chunk(
        tenant_id="tenant-a",
        source_id="DOC-POLICY-001",
        media_type="text/markdown",
        document_id="policy-001",
        document_version=version,
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        allowed_groups=frozenset({"finance"}),
        data_owner="policy-team",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id="tenant-a",
            document_id="policy-001",
            document_version=version,
            content_hash=content_hash,
            chunk_index=index,
        ),
        chunk_index=index,
        text=f"Synthetic contract chunk {index}",
        embedding=vector(index),
    )


def test_fake_implements_vector_store_protocol() -> None:
    assert isinstance(InMemoryVectorStore(), VectorStore)


def test_create_upsert_search_delete_contract_is_idempotent() -> None:
    async def scenario() -> None:
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_001_contract")
        first = chunk()
        second_version = chunk(version="v2")
        await store.create_or_validate_collection(specification)
        await store.create_or_validate_collection(specification)
        await store.upsert_chunks(specification, (first,), auth(Role.INGESTOR))
        await store.upsert_chunks(specification, (first,), auth(Role.INGESTOR))
        await store.upsert_chunks(
            specification,
            (second_version,),
            auth(Role.INGESTOR),
        )
        assert (
            await store.count_by_document_version(
                specification,
                "policy-001",
                "v2",
                auth(Role.ADMIN),
            )
            == 1
        )

        results = await store.search(
            specification,
            Query(text="policy", top_k=5),
            vector(),
            auth(Role.READER),
        )
        assert {result.chunk_id for result in results} == {
            first.chunk_id,
            second_version.chunk_id,
        }

        await store.delete_by_document_version(
            specification,
            "policy-001",
            "v2",
            auth(Role.ADMIN),
        )
        assert (
            await store.count_by_document_version(
                specification,
                "policy-001",
                "v2",
                auth(Role.ADMIN),
            )
            == 0
        )
        remaining = await store.search(
            specification,
            Query(text="policy", top_k=5),
            vector(),
            auth(Role.READER),
        )
        assert [result.chunk_id for result in remaining] == [first.chunk_id]

        await store.delete_by_document_id(
            specification,
            "policy-001",
            auth(Role.ADMIN),
        )
        assert (
            await store.search(
                specification,
                Query(text="policy"),
                vector(),
                auth(Role.READER),
            )
            == ()
        )

    asyncio.run(scenario())


def test_contract_normalizes_validation_authorization_and_availability_failures() -> None:
    async def scenario() -> None:
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_001_failures")
        await store.create_or_validate_collection(specification)
        with pytest.raises(VectorStoreValidationError):
            await store.upsert_chunks(specification, (), auth(Role.INGESTOR))
        with pytest.raises(VectorStoreAuthorizationError):
            await store.upsert_chunks(specification, (chunk(),), auth(Role.READER))
        store.set_available(False)
        assert not await store.healthcheck()
        with pytest.raises(VectorStoreUnavailableError) as failure:
            await store.search(
                specification,
                Query(text="policy"),
                vector(),
                auth(Role.READER),
            )
        assert "InMemoryVectorStore" not in str(failure.value)

    asyncio.run(scenario())


def test_collection_and_vector_mismatch_fail_before_mutation_or_query() -> None:
    async def scenario() -> None:
        store = InMemoryVectorStore()
        specification = CollectionSpec(name="w2_001_mismatch")
        await store.create_or_validate_collection(specification)
        bypassed = CollectionSpec.model_construct(
            name="w2_001_mismatch",
            embedding_model_id=specification.embedding_model_id,
            embedding_revision=specification.embedding_revision,
            dimension=768,
            license=specification.license,
            normalized=True,
            metric=specification.metric,
        )
        with pytest.raises(VectorStoreValidationError):
            await store.upsert_chunks(bypassed, (chunk(),), auth(Role.INGESTOR))
        with pytest.raises(VectorStoreValidationError):
            await store.search(
                specification,
                Query(text="policy"),
                (1.0,),
                auth(Role.READER),
            )

    asyncio.run(scenario())
