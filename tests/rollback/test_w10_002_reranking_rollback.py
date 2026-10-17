"""Rollback tests proving default-off restoration of baseline behavior."""

from __future__ import annotations

import asyncio

from tests.fakes.w10_002_reranking import StaticVectorStore, reader_auth, retrieved_chunks

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query
from enterprise_ai_platform.retrieval.service import RetrievalService


def test_omitting_reranker_restores_exact_baseline_order_and_candidate_count() -> None:
    async def scenario() -> None:
        baseline = retrieved_chunks("first", "second", "third")
        store = StaticVectorStore(baseline)
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=store,
            collection_spec=CollectionSpec(name="w10_002_rollback"),
        )

        results = await service.retrieve(Query(text="query", top_k=2), reader_auth())

        assert results == baseline[:2]
        assert store.queries[0].top_k == 2

    asyncio.run(scenario())
