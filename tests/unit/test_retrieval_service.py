"""Unit tests for provider-neutral retrieval orchestration."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from enterprise_ai_platform.embeddings.errors import (
    EmbeddingContractMismatchError,
    EmbeddingProviderFailure,
)
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.errors import (
    VectorStoreAuthorizationError,
    VectorStoreTimeoutError,
    VectorStoreValidationError,
)
from enterprise_ai_platform.retrieval.models import (
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
from enterprise_ai_platform.retrieval.service import RetrievalService


class RecordingEmbedder(FakeEmbeddingProvider):
    def __init__(self, *, fail: bool = False) -> None:
        super().__init__(fail=fail)
        self.queries: list[str] = []

    async def embed_query(self, text: str) -> tuple[float, ...]:
        self.queries.append(text)
        return await super().embed_query(text)


class RecordingStore(InMemoryVectorStore):
    def __init__(self) -> None:
        super().__init__()
        self.search_calls = 0
        self.search_timeouts: list[float | None] = []

    async def search(self, *args, timeout_seconds=None, **kwargs):  # type: ignore[no-untyped-def]
        self.search_calls += 1
        self.search_timeouts.append(timeout_seconds)
        return await super().search(
            *args,
            timeout_seconds=timeout_seconds,
            **kwargs,
        )


class MismatchedEmbedder(FakeEmbeddingProvider):
    @property
    def dimension(self) -> int:
        return 768


def auth(*roles: Role, expires_at: datetime | None = None) -> AuthContext:
    return AuthContext(
        subject_id="retrieval-service-user",
        tenant_id="tenant-a",
        roles=frozenset(roles),
        clearance=Classification.INTERNAL,
        expires_at=expires_at,
    )


def chunk(vector: tuple[float, ...]) -> Chunk:
    content_hash = "a" * 64
    document_id = "retrieval-service-document"
    return Chunk(
        tenant_id="tenant-a",
        source_id="DOC-RETRIEVAL-SERVICE",
        media_type="text/plain",
        document_id=document_id,
        document_version="v1",
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        allowed_groups=frozenset(),
        data_owner="retrieval-team",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id="tenant-a",
            document_id=document_id,
            document_version="v1",
            content_hash=content_hash,
            chunk_index=0,
        ),
        chunk_index=0,
        text="Synthetic retrieval service fixture",
        embedding=vector,
    )


def test_retrieve_embeds_then_searches_with_the_approved_timeout() -> None:
    async def scenario() -> None:
        embedder = RecordingEmbedder()
        store = RecordingStore()
        specification = CollectionSpec(name="w2_004_service_unit")
        query = Query(text="approved retrieval question", top_k=5)
        vector = await embedder.embed_query(query.text)
        embedder.queries.clear()
        await store.create_or_validate_collection(specification)
        await store.upsert_chunks(
            specification,
            (chunk(vector),),
            auth(Role.INGESTOR),
        )
        service = RetrievalService(
            embedder=embedder,
            vector_store=store,
            collection_spec=specification,
            timeout_seconds=7.0,
        )

        results = await service.retrieve(query, auth(Role.READER))

        assert [result.source_id for result in results] == [
            "DOC-RETRIEVAL-SERVICE"
        ]
        assert embedder.queries == [query.text]
        assert store.search_calls == 1
        assert store.search_timeouts == [7.0]

    asyncio.run(scenario())


def test_invalid_collection_or_embedding_contract_fails_during_construction() -> None:
    store = RecordingStore()
    bypassed = CollectionSpec.model_construct(
        name="w2_004_invalid_service",
        embedding_model_id="sentence-transformers/all-MiniLM-L6-v2",
        embedding_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
        dimension=768,
        license="Apache-2.0",
        normalized=True,
        metric="cosine",
    )
    with pytest.raises(VectorStoreValidationError):
        RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=store,
            collection_spec=bypassed,
        )
    with pytest.raises(EmbeddingContractMismatchError):
        RetrievalService(
            embedder=MismatchedEmbedder(),
            vector_store=store,
            collection_spec=CollectionSpec(name="w2_004_embedder_mismatch"),
        )


def test_expired_authorization_stops_before_embedding_or_search() -> None:
    async def scenario() -> None:
        embedder = RecordingEmbedder()
        store = RecordingStore()
        service = RetrievalService(
            embedder=embedder,
            vector_store=store,
            collection_spec=CollectionSpec(name="w2_004_expired_context"),
        )
        expired = datetime.now(UTC) - timedelta(seconds=1)

        with pytest.raises(VectorStoreAuthorizationError):
            await service.retrieve(
                Query(text="must not reach embedding"),
                auth(Role.READER, expires_at=expired),
            )

        assert embedder.queries == []
        assert store.search_calls == 0

    asyncio.run(scenario())


def test_timeout_is_normalized_and_cancellation_is_not_swallowed() -> None:
    class BlockingEmbedder(RecordingEmbedder):
        def __init__(self) -> None:
            super().__init__()
            self.started = asyncio.Event()
            self.release = asyncio.Event()

        async def embed_query(self, text: str) -> tuple[float, ...]:
            self.queries.append(text)
            self.started.set()
            await self.release.wait()
            return await FakeEmbeddingProvider.embed_query(self, text)

    async def scenario() -> None:
        timed_embedder = BlockingEmbedder()
        timed = RetrievalService(
            embedder=timed_embedder,
            vector_store=RecordingStore(),
            collection_spec=CollectionSpec(name="w2_004_timeout"),
            timeout_seconds=0.01,
        )
        with pytest.raises(VectorStoreTimeoutError):
            await timed.retrieve(Query(text="private timeout query"), auth(Role.READER))

        cancelled_embedder = BlockingEmbedder()
        cancelled_store = RecordingStore()
        cancelled = RetrievalService(
            embedder=cancelled_embedder,
            vector_store=cancelled_store,
            collection_spec=CollectionSpec(name="w2_004_cancelled"),
        )
        task = asyncio.create_task(
            cancelled.retrieve(Query(text="private cancelled query"), auth(Role.READER))
        )
        await cancelled_embedder.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert cancelled_store.search_calls == 0

    asyncio.run(scenario())


def test_embedding_failure_exposes_no_query_text() -> None:
    service = RetrievalService(
        embedder=RecordingEmbedder(fail=True),
        vector_store=RecordingStore(),
        collection_spec=CollectionSpec(name="w2_004_redaction"),
    )
    sensitive_query = "private customer question"
    with pytest.raises(EmbeddingProviderFailure) as failure:
        asyncio.run(service.retrieve(Query(text=sensitive_query), auth(Role.READER)))
    assert sensitive_query not in str(failure.value)
