"""Owner-opted local Qdrant integration contract."""

from __future__ import annotations

import asyncio
import os

import pytest
from qdrant_client import AsyncQdrantClient

from enterprise_ai_platform.retrieval.adapters.qdrant import QdrantVectorStore
from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
    AuthContext,
    Chunk,
    Classification,
    CollectionSpec,
    IngestionStatus,
    PiiStatus,
    Query,
    Role,
    deterministic_chunk_id,
)

RUN_LOCAL_QDRANT = "ENTERPRISE_AI_RUN_QDRANT_INTEGRATION"
QDRANT_INTEGRATION_URL = "ENTERPRISE_AI_QDRANT_INTEGRATION_URL"
INTERNAL_QDRANT_URL = "http://qdrant:6333"


class RetryHealthClient:
    def __init__(self) -> None:
        self.calls = 0

    async def get_collections(self) -> object:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("synthetic unavailable boundary")
        return object()


def vector() -> tuple[float, ...]:
    return tuple([1.0] + [0.0] * (APPROVED_EMBEDDING_DIMENSION - 1))


def auth(role: Role) -> AuthContext:
    return AuthContext(
        subject_id="qdrant-contract-user",
        tenant_id="tenant-a",
        roles=frozenset({role}),
        clearance=Classification.RESTRICTED,
    )


def chunk() -> Chunk:
    content_hash = "d" * 64
    return Chunk(
        tenant_id="tenant-a",
        source_id="DOC-QDRANT-POLICY",
        media_type="text/plain",
        document_id="policy-qdrant",
        document_version="v1",
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        allowed_groups=frozenset(),
        data_owner="policy-team",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id="tenant-a",
            document_id="policy-qdrant",
            document_version="v1",
            content_hash=content_hash,
            chunk_index=0,
        ),
        chunk_index=0,
        text="Synthetic local Qdrant contract text",
        embedding=vector(),
    )


def approved_internal_qdrant_url() -> str:
    if os.getenv(RUN_LOCAL_QDRANT) != "1":
        pytest.skip(f"set {RUN_LOCAL_QDRANT}=1 only in the approved test runner")

    url = os.getenv(QDRANT_INTEGRATION_URL)
    if url != INTERNAL_QDRANT_URL:
        pytest.fail(
            f"{QDRANT_INTEGRATION_URL} must be the approved internal service URL"
        )
    return url


def test_qdrant_retry_is_bounded_and_uses_injected_approved_delay() -> None:
    async def scenario() -> None:
        client = RetryHealthClient()
        delays: list[float] = []

        async def record_sleep(delay: float) -> None:
            delays.append(delay)

        store = QdrantVectorStore(
            client,
            retry_delay=lambda: 0.15,
            sleep=record_sleep,
        )
        assert await store.healthcheck()
        assert client.calls == 2
        assert delays == [0.15]

    asyncio.run(scenario())


def test_local_qdrant_round_trip_and_collection_cleanup() -> None:
    qdrant_url = approved_internal_qdrant_url()

    async def scenario() -> None:
        client = AsyncQdrantClient(url=qdrant_url, timeout=5)
        store = QdrantVectorStore(client)
        specification = CollectionSpec(name="w2_001_contract_test")
        source_chunk = chunk()
        try:
            assert await store.healthcheck()
            collections = await client.get_collections()
            assert collections.collections == []
            await store.create_or_validate_collection(specification)
            await store.upsert_chunks(specification, (source_chunk,), auth(Role.INGESTOR))
            results = await store.search(
                specification,
                Query(text="policy"),
                vector(),
                auth(Role.READER),
            )
            assert [result.chunk_id for result in results] == [source_chunk.chunk_id]
            await store.delete_by_document_version(
                specification,
                source_chunk.document_id,
                source_chunk.document_version,
                auth(Role.ADMIN),
            )
            assert (
                await store.search(
                    specification,
                    Query(text="policy"),
                    vector(),
                    auth(Role.READER),
                )
                == ()
            )
        finally:
            try:
                if await client.collection_exists(specification.name):
                    await client.delete_collection(specification.name)
                assert not await client.collection_exists(specification.name)
            finally:
                await client.close()

    asyncio.run(scenario())
