"""Security tests for authorization revalidation and safe reranker failures."""

from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.errors import VectorStoreAuthorizationError
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query, RetrievedChunk
from enterprise_ai_platform.retrieval.service import RetrievalService
from tests.fakes.w10_001_hybrid_retrieval import make_chunk
from tests.fakes.w10_002_reranking import (
    RecordingReranker,
    StaticVectorStore,
    reader_auth,
    retrieved_chunks,
)


def test_provider_returned_unauthorized_candidate_aborts_before_reranking() -> None:
    async def scenario() -> None:
        unauthorized = make_chunk(0, tenant_id="tenant-b")
        returned = RetrievedChunk(**unauthorized.model_dump(), score=1.0)
        reranker = RecordingReranker()
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=StaticVectorStore((returned,)),
            collection_spec=CollectionSpec(name="w10_002_security"),
            reranker=reranker,
        )

        with pytest.raises(VectorStoreAuthorizationError) as failure:
            await service.retrieve(Query(text="private query"), reader_auth())

        assert reranker.calls == []
        assert "private query" not in str(failure.value)

    asyncio.run(scenario())


def test_unknown_reranker_identity_cannot_replace_authorized_candidates() -> None:
    async def scenario() -> None:
        baseline = retrieved_chunks("first", "second")
        reranker = RecordingReranker(order=("f" * 64, baseline[0].chunk_id))
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=StaticVectorStore(baseline),
            collection_spec=CollectionSpec(name="w10_002_unknown_identity"),
            reranker=reranker,
        )

        assert await service.retrieve(Query(text="query", top_k=2), reader_auth()) == baseline

    asyncio.run(scenario())
