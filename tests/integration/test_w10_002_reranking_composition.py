"""Composition tests for optional reranking after authorized retrieval."""

from __future__ import annotations

import asyncio

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.errors import RerankerUnavailableError
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query
from enterprise_ai_platform.retrieval.service import RetrievalService
from tests.fakes.w10_002_reranking import (
    RecordingReranker,
    StaticVectorStore,
    reader_auth,
    retrieved_chunks,
)


def test_service_fetches_twenty_candidates_and_returns_requested_reranked_results() -> None:
    async def scenario() -> None:
        baseline = retrieved_chunks("alpha", "alpha beta", "beta")
        store = StaticVectorStore(baseline)
        reranker = RecordingReranker(
            order=(baseline[1].chunk_id, baseline[0].chunk_id, baseline[2].chunk_id)
        )
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=store,
            collection_spec=CollectionSpec(name="w10_002_composition"),
            reranker=reranker,
        )

        results = await service.retrieve(Query(text="alpha beta", top_k=2), reader_auth())

        assert [result.chunk_id for result in results] == [
            baseline[1].chunk_id,
            baseline[0].chunk_id,
        ]
        assert store.queries[0].top_k == 20
        assert len(reranker.calls) == 1

    asyncio.run(scenario())


def test_approved_reranker_failure_returns_exact_baseline_order() -> None:
    async def scenario() -> None:
        baseline = retrieved_chunks("first", "second", "third")
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=StaticVectorStore(baseline),
            collection_spec=CollectionSpec(name="w10_002_fallback"),
            reranker=RecordingReranker(failure=RerankerUnavailableError()),
        )

        results = await service.retrieve(Query(text="query", top_k=2), reader_auth())

        assert results == baseline[:2]

    asyncio.run(scenario())
