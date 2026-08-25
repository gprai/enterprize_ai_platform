from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.embeddings.base import (
    Embedder,
    EmbeddingContract,
    assert_embedding_contract,
)
from enterprise_ai_platform.embeddings.errors import EmbeddingContractMismatchError
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider

APPROVED_CONTRACT = EmbeddingContract(
    model_id="sentence-transformers/all-MiniLM-L6-v2",
    model_revision="1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    dimension=384,
    normalized=True,
    metric="cosine",
)


def test_fake_implements_the_provider_neutral_async_contract() -> None:
    provider = FakeEmbeddingProvider()

    assert isinstance(provider, Embedder)
    assert len(asyncio.run(provider.embed_query("query"))) == 384
    assert len(asyncio.run(provider.embed_documents(["one", "two"]))) == 2


def test_approved_provider_matches_approved_collection_contract() -> None:
    assert_embedding_contract(FakeEmbeddingProvider(), APPROVED_CONTRACT)


@pytest.mark.parametrize(
    ("provider", "contract"),
    [
        (
            FakeEmbeddingProvider(model_id="unapproved/model"),
            APPROVED_CONTRACT,
        ),
        (
            FakeEmbeddingProvider(model_revision="mutable-main"),
            APPROVED_CONTRACT,
        ),
        (
            FakeEmbeddingProvider(dimension=768),
            APPROVED_CONTRACT,
        ),
        (
            FakeEmbeddingProvider(normalized=False),
            APPROVED_CONTRACT,
        ),
        (
            FakeEmbeddingProvider(),
            EmbeddingContract(
                model_id=APPROVED_CONTRACT.model_id,
                model_revision=APPROVED_CONTRACT.model_revision,
                dimension=APPROVED_CONTRACT.dimension,
                normalized=APPROVED_CONTRACT.normalized,
                metric="dot",
            ),
        ),
    ],
)
def test_mismatch_fails_before_vector_store_access(
    provider: FakeEmbeddingProvider,
    contract: EmbeddingContract,
) -> None:
    vector_store_calls = 0

    def guarded_vector_query() -> None:
        nonlocal vector_store_calls
        assert_embedding_contract(provider, contract)
        vector_store_calls += 1

    with pytest.raises(EmbeddingContractMismatchError):
        guarded_vector_query()

    assert vector_store_calls == 0
