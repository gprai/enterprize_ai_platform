"""Cleanliness tests for timeout and cancellation capacity release."""

from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query
from enterprise_ai_platform.retrieval.service import RetrievalService
from tests.fakes.w10_002_reranking import (
    RecordingReranker,
    StaticVectorStore,
    reader_auth,
    retrieved_chunks,
)


def test_reranker_timeout_releases_capacity_and_leaves_no_task_owned_state() -> None:
    async def scenario() -> None:
        baseline = retrieved_chunks("first", "second")
        reranker = RecordingReranker(blocked=True)
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=StaticVectorStore(baseline),
            collection_spec=CollectionSpec(name="w10_002_timeout_cleanliness"),
            reranker=reranker,
        )

        assert await service.retrieve(Query(text="query", top_k=2), reader_auth()) == baseline
        assert service._reranker_inflight == 0

    asyncio.run(scenario())


def test_cancellation_releases_capacity_without_returning_partial_results() -> None:
    async def scenario() -> None:
        baseline = retrieved_chunks("first", "second")
        reranker = RecordingReranker(blocked=True)
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=StaticVectorStore(baseline),
            collection_spec=CollectionSpec(name="w10_002_cancel_cleanliness"),
            reranker=reranker,
        )
        task = asyncio.create_task(service.retrieve(Query(text="query", top_k=2), reader_auth()))
        await reranker.started.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert service._reranker_inflight == 0

    asyncio.run(scenario())
