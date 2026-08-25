from __future__ import annotations

import asyncio
import math

import pytest

from enterprise_ai_platform.embeddings.base import EmbeddingMetric
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingInputError,
    EmbeddingProviderFailure,
)
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider


class MetricSpy:
    def __init__(self) -> None:
        self.metrics: list[EmbeddingMetric] = []

    def record(self, metric: EmbeddingMetric) -> None:
        self.metrics.append(metric)


def test_fake_embedder_is_deterministic_normalized_and_exactly_384_dimensions() -> None:
    provider = FakeEmbeddingProvider()

    first = asyncio.run(provider.embed_query("tenant-safe query"))
    second = asyncio.run(provider.embed_query("tenant-safe query"))

    assert first == second
    assert len(first) == 384
    assert math.isclose(math.sqrt(sum(value * value for value in first)), 1.0)


def test_fake_embedder_separates_different_inputs() -> None:
    provider = FakeEmbeddingProvider()

    first = asyncio.run(provider.embed_query("first"))
    second = asyncio.run(provider.embed_query("second"))

    assert first != second


def test_fake_embedder_preserves_document_order() -> None:
    provider = FakeEmbeddingProvider()

    documents = asyncio.run(provider.embed_documents(["first", "second"]))

    assert documents[0] == asyncio.run(provider.embed_query("first"))
    assert documents[1] == asyncio.run(provider.embed_query("second"))


def test_fake_embedder_has_controllable_stable_failure() -> None:
    provider = FakeEmbeddingProvider(fail=True)

    with pytest.raises(EmbeddingProviderFailure) as caught:
        asyncio.run(provider.embed_query("must not appear in the error"))

    assert caught.value.code == "embedding_provider_failure"
    assert "must not appear" not in str(caught.value)


def test_fake_embedder_rejects_empty_or_blank_input() -> None:
    provider = FakeEmbeddingProvider()

    with pytest.raises(EmbeddingInputError):
        asyncio.run(provider.embed_documents([]))
    with pytest.raises(EmbeddingInputError):
        asyncio.run(provider.embed_query("  "))


def test_fake_metrics_contain_counts_and_no_text() -> None:
    recorder = MetricSpy()
    provider = FakeEmbeddingProvider(metric_recorder=recorder)

    asyncio.run(provider.embed_documents(["private alpha", "private beta"]))

    assert recorder.metrics == [
        EmbeddingMetric(
            operation="documents",
            item_count=2,
            batch_count=1,
            duration_seconds=0.0,
            outcome="success",
        )
    ]
    assert "private" not in repr(recorder.metrics)


def test_fake_embedder_rejects_more_than_1024_items() -> None:
    provider = FakeEmbeddingProvider()

    with pytest.raises(EmbeddingInputError):
        asyncio.run(provider.embed_documents(["item"] * 1_025))
