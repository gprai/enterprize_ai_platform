"""Offline rollback contract for W10-001 retrieval mode and index identity."""

from __future__ import annotations

import asyncio

import pytest
from tests.fakes.w10_001_hybrid_retrieval import (
    FakeHybridOpenSearchClient,
    approved_vector,
    make_chunk,
    make_hit,
    reader_auth,
)

from enterprise_ai_platform.retrieval.adapters.opensearch import OpenSearchVectorStore
from enterprise_ai_platform.retrieval.errors import CollectionMismatchError
from enterprise_ai_platform.retrieval.hybrid import RetrievalMode
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query


def test_vector_mode_restores_the_single_channel_mapping_and_query() -> None:
    async def scenario() -> None:
        source = make_chunk(0)
        client = FakeHybridOpenSearchClient(vector_hits=[make_hit(source, 1.0)])
        store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.VECTOR)
        specification = CollectionSpec(name="enterprise_ai_sandbox")

        await store.create_or_validate_collection(specification)
        results = await store.search(
            specification,
            Query(text="synthetic"),
            approved_vector(),
            reader_auth(),
        )

        assert [result.chunk_id for result in results] == [source.chunk_id]
        assert [call["channel"] for call in client.search_calls] == ["vector"]
        mappings = client.indices.created[specification.name]["mappings"]
        assert mappings["properties"]["text"] == {"type": "text", "index": False}
        identity = mappings["_meta"]["enterprise_ai_retrieval_identity"]
        assert identity["mode"] == "vector"
        assert identity["lexical_analyzer"] is None

    asyncio.run(scenario())


def test_mode_change_requires_an_exact_owner_controlled_index_rebuild() -> None:
    async def scenario() -> None:
        client = FakeHybridOpenSearchClient()
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        vector_store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.VECTOR)
        hybrid_store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.HYBRID)
        await vector_store.create_or_validate_collection(specification)

        with pytest.raises(CollectionMismatchError):
            await hybrid_store.create_or_validate_collection(specification)

        assert tuple(client.indices.created) == (specification.name,)

    asyncio.run(scenario())
