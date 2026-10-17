"""Injected OpenSearch composition tests for W10-001 hybrid retrieval."""

from __future__ import annotations

import asyncio
from pathlib import Path

from enterprise_ai_platform.retrieval.adapters.opensearch import OpenSearchVectorStore
from enterprise_ai_platform.retrieval.hybrid import RetrievalMode
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query
from tests.fakes.w10_001_hybrid_retrieval import (
    FakeHybridOpenSearchClient,
    approved_vector,
    make_chunk,
    make_hit,
    reader_auth,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def test_local_and_sandbox_mode_selection_is_explicit() -> None:
    local_environment = (REPOSITORY_ROOT / ".env.example").read_text(encoding="utf-8")
    sandbox_config = (REPOSITORY_ROOT / "deploy/k8s/configmap.yaml").read_text(encoding="utf-8")

    assert local_environment.count("ENTERPRISE_AI_RAG_RETRIEVAL_MODE=vector") == 1
    assert sandbox_config.count("ENTERPRISE_AI_RAG_RETRIEVAL_MODE: hybrid") == 1


def test_hybrid_mapping_queries_filters_fusion_and_concurrency_are_exact() -> None:
    async def scenario() -> None:
        vector_first = make_chunk(0, text="semantic access policy")
        lexical_first = make_chunk(1, text="POLICY-EXACT-42")
        client = FakeHybridOpenSearchClient(
            vector_hits=[make_hit(vector_first, 10.0), make_hit(lexical_first, 0.0)],
            lexical_hits=[make_hit(lexical_first, 20.0), make_hit(vector_first, 0.0)],
        )
        store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.HYBRID)
        specification = CollectionSpec(name="enterprise_ai_sandbox")

        await store.create_or_validate_collection(specification)
        results = await store.search(
            specification,
            Query(text="POLICY-EXACT-42", top_k=2),
            approved_vector(),
            reader_auth(),
        )

        assert [result.chunk_id for result in results] == [
            lexical_first.chunk_id,
            vector_first.chunk_id,
        ]
        assert [result.score for result in results] == [0.5, 0.5]
        assert client.maximum_active_searches == 2
        assert [call["channel"] for call in client.search_calls] == ["vector", "lexical"]
        vector_body, lexical_body = [call["body"] for call in client.search_calls]
        assert vector_body["size"] == lexical_body["size"] == 20
        assert vector_body["query"]["bool"]["filter"] == lexical_body["query"]["bool"]["filter"]
        mappings = client.indices.created[specification.name]["mappings"]
        assert mappings["properties"]["text"] == {
            "type": "text",
            "analyzer": "standard",
            "search_analyzer": "standard",
            "similarity": "BM25",
        }
        assert mappings["_meta"]["enterprise_ai_retrieval_identity"]["mode"] == "hybrid"

    asyncio.run(scenario())


def test_each_channel_keeps_two_total_attempts_not_two_retries() -> None:
    async def scenario() -> None:
        source = make_chunk(0)
        client = FakeHybridOpenSearchClient(
            vector_hits=[make_hit(source, 1.0)],
            lexical_hits=[make_hit(source, 1.0)],
        )
        client.failures_remaining["vector"] = 1
        client.failures_remaining["lexical"] = 1
        delays: list[float] = []

        async def record_sleep(delay: float) -> None:
            delays.append(delay)

        store = OpenSearchVectorStore(
            client,
            retrieval_mode=RetrievalMode.HYBRID,
            retry_delay=lambda: 0.1,
            sleep=record_sleep,
        )
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        await store.create_or_validate_collection(specification)

        results = await store.search(
            specification,
            Query(text="synthetic"),
            approved_vector(),
            reader_auth(),
        )

        assert [result.chunk_id for result in results] == [source.chunk_id]
        assert [call["channel"] for call in client.search_calls].count("vector") == 2
        assert [call["channel"] for call in client.search_calls].count("lexical") == 2
        assert len(client.search_calls) == 4
        assert delays == [0.1, 0.1]

    asyncio.run(scenario())
