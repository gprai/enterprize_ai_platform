"""Business acceptance for authorized deterministic W10-001 hybrid retrieval."""

from __future__ import annotations

import asyncio

from enterprise_ai_platform.retrieval.adapters.opensearch import OpenSearchVectorStore
from enterprise_ai_platform.retrieval.hybrid import RetrievalMode
from enterprise_ai_platform.retrieval.models import Citation, CollectionSpec, Query
from tests.fakes.w10_001_hybrid_retrieval import (
    FakeHybridOpenSearchClient,
    approved_vector,
    make_chunk,
    make_hit,
    reader_auth,
)


def test_hybrid_retrieval_preserves_authorization_citations_and_determinism() -> None:
    async def scenario() -> None:
        semantic = make_chunk(0, text="Employees may request approved access")
        exact = make_chunk(1, text="CONTROL-RAG-002")
        client = FakeHybridOpenSearchClient(
            vector_hits=[make_hit(semantic, 9.0), make_hit(exact, 1.0)],
            lexical_hits=[make_hit(exact, 12.0), make_hit(semantic, 2.0)],
        )
        store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.HYBRID)
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        await store.create_or_validate_collection(specification)
        query = Query(text="CONTROL-RAG-002", top_k=2)

        first = await store.search(specification, query, approved_vector(), reader_auth())
        second = await store.search(specification, query, approved_vector(), reader_auth())
        citations = tuple(
            Citation(
                source_id=result.source_id,
                document_id=result.document_id,
                document_version=result.document_version,
                chunk_id=result.chunk_id,
            )
            for result in first
        )

        assert first == second
        assert [result.chunk_id for result in first] == [exact.chunk_id, semantic.chunk_id]
        assert all(result.tenant_id == "tenant-a" for result in first)
        assert [citation.chunk_id for citation in citations] == [
            exact.chunk_id,
            semantic.chunk_id,
        ]
        assert [citation.source_id for citation in citations] == [
            exact.source_id,
            semantic.source_id,
        ]
        assert all(
            result.__class__.__module__.startswith("enterprise_ai_platform") for result in first
        )

    asyncio.run(scenario())
