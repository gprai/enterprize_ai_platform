"""Zero-residue checks for the injected W10-001 hybrid boundary."""

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


def test_hybrid_search_leaves_no_tasks_files_or_external_resources(tmp_path: Path) -> None:
    async def scenario() -> None:
        source = make_chunk(0)
        client = FakeHybridOpenSearchClient(
            vector_hits=[make_hit(source, 1.0)],
            lexical_hits=[make_hit(source, 1.0)],
        )
        store = OpenSearchVectorStore(client, retrieval_mode=RetrievalMode.HYBRID)
        specification = CollectionSpec(name="enterprise_ai_sandbox")
        await store.create_or_validate_collection(specification)
        current = asyncio.current_task()
        before = {task for task in asyncio.all_tasks() if task is not current}

        results = await store.search(
            specification,
            Query(text="synthetic"),
            approved_vector(),
            reader_auth(),
        )

        await asyncio.sleep(0)
        after = {task for task in asyncio.all_tasks() if task is not current}
        assert [result.chunk_id for result in results] == [source.chunk_id]
        assert before == after
        assert client.active_searches == 0
        assert client.indices.created.keys() == {specification.name}

    asyncio.run(scenario())
    assert tuple(tmp_path.iterdir()) == ()
