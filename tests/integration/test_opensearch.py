"""Injected OpenSearch boundary tests; live AWS remains explicitly skipped."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from enterprise_ai_platform.retrieval.adapters.opensearch import OpenSearchVectorStore
from enterprise_ai_platform.retrieval.errors import VectorStoreAuthorizationError
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


def vector() -> tuple[float, ...]:
    return tuple([1.0] + [0.0] * (APPROVED_EMBEDDING_DIMENSION - 1))


def chunk(tenant_id: str = "tenant-a") -> Chunk:
    content_hash = "c" * 64
    return Chunk(
        tenant_id=tenant_id,
        source_id="DOC-OPENSEARCH-POLICY",
        media_type="text/plain",
        document_id="policy-opensearch",
        document_version="v1",
        classification=Classification.CONFIDENTIAL,
        allowed_roles=frozenset({Role.READER}),
        allowed_groups=frozenset(),
        data_owner="policy-team",
        content_hash=content_hash,
        pii_status=PiiStatus.REDACTED,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id=tenant_id,
            document_id="policy-opensearch",
            document_version="v1",
            content_hash=content_hash,
            chunk_index=0,
        ),
        chunk_index=0,
        text="Synthetic OpenSearch boundary text",
        embedding=vector(),
    )


def auth(role: Role) -> AuthContext:
    return AuthContext(
        subject_id="opensearch-test-user",
        tenant_id="tenant-a",
        roles=frozenset({role}),
        clearance=Classification.RESTRICTED,
    )


class FakeIndices:
    def __init__(self) -> None:
        self.created: dict[str, dict[str, Any]] = {}

    async def exists(self, *, index: str) -> bool:
        return index in self.created

    async def create(self, *, index: str, body: dict[str, Any]) -> dict[str, bool]:
        self.created[index] = body
        return {"acknowledged": True}

    async def get_mapping(self, *, index: str) -> dict[str, Any]:
        return {index: {"mappings": self.created[index]["mappings"]}}


class FakeCluster:
    async def health(self) -> dict[str, str]:
        return {"status": "green"}


class RetryCluster:
    def __init__(self) -> None:
        self.calls = 0

    async def health(self) -> dict[str, str]:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("synthetic unavailable boundary")
        return {"status": "green"}


class FakeOpenSearchClient:
    def __init__(self) -> None:
        self.indices = FakeIndices()
        self.cluster = FakeCluster()
        self.documents: dict[str, dict[str, Any]] = {}
        self.last_search: dict[str, Any] | None = None

    async def index(
        self,
        *,
        index: str,
        id: str,
        body: dict[str, Any],
        refresh: str,
    ) -> dict[str, str]:
        del index, refresh
        self.documents[id] = body
        return {"result": "created"}

    async def search(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        del index
        self.last_search = body
        hits = [
            {"_id": document_id, "_score": 1.0, "_source": document}
            for document_id, document in self.documents.items()
        ]
        return {"hits": {"hits": hits}}

    async def delete_by_query(
        self,
        *,
        index: str,
        body: dict[str, Any],
        refresh: bool,
        conflicts: str,
    ) -> dict[str, int]:
        del index, refresh, conflicts
        filters = body["query"]["bool"]["filter"]
        tenant_id = filters[0]["term"]["tenant_id"]
        document_id = filters[1]["term"]["document_id"]
        document_version = filters[2]["term"]["document_version"] if len(filters) == 3 else None
        delete_ids = [
            key
            for key, value in self.documents.items()
            if value["tenant_id"] == tenant_id
            and value["document_id"] == document_id
            and (document_version is None or value["document_version"] == document_version)
        ]
        for key in delete_ids:
            del self.documents[key]
        return {"deleted": len(delete_ids)}

    async def count(self, *, index: str, body: dict[str, Any]) -> dict[str, int]:
        del index
        filters = body["query"]["bool"]["filter"]
        expected = {next(iter(item["term"])): next(iter(item["term"].values())) for item in filters}
        return {
            "count": sum(
                1
                for document in self.documents.values()
                if all(document[key] == value for key, value in expected.items())
            )
        }


def test_injected_opensearch_boundary_carries_spec_filters_and_no_sdk_results() -> None:
    async def scenario() -> None:
        client = FakeOpenSearchClient()
        store = OpenSearchVectorStore(client)
        specification = CollectionSpec(name="w2_001_opensearch")
        source_chunk = chunk()

        await store.create_or_validate_collection(specification)
        await store.upsert_chunks(specification, (source_chunk,), auth(Role.INGESTOR))
        results = await store.search(
            specification,
            Query(text="policy"),
            vector(),
            auth(Role.READER),
        )

        assert [result.chunk_id for result in results] == [source_chunk.chunk_id]
        assert client.last_search is not None
        filters = client.last_search["query"]["bool"]["filter"]
        assert {"term": {"tenant_id": "tenant-a"}} in filters
        assert "source_id" in client.indices.created[specification.name]["mappings"]["properties"]
        assert "media_type" in client.indices.created[specification.name]["mappings"]["properties"]
        exception_properties = client.indices.created[specification.name]["mappings"]["properties"][
            "approved_exception"
        ]["properties"]
        assert exception_properties["document_id"] == {"type": "keyword"}
        assert exception_properties["entity_types"] == {"type": "keyword"}
        assert all(
            result.__class__.__module__.startswith("enterprise_ai_platform") for result in results
        )
        assert await store.healthcheck()
        assert (
            await store.count_by_document_version(
                specification,
                source_chunk.document_id,
                source_chunk.document_version,
                auth(Role.ADMIN),
            )
            == 1
        )

        await store.delete_by_document_version(
            specification,
            source_chunk.document_id,
            source_chunk.document_version,
            auth(Role.ADMIN),
        )
        assert client.documents == {}
        assert (
            await store.count_by_document_version(
                specification,
                source_chunk.document_id,
                source_chunk.document_version,
                auth(Role.ADMIN),
            )
            == 0
        )

    asyncio.run(scenario())


def test_opensearch_retry_is_bounded_and_uses_injected_approved_delay() -> None:
    async def scenario() -> None:
        client = FakeOpenSearchClient()
        client.cluster = RetryCluster()
        delays: list[float] = []

        async def record_sleep(delay: float) -> None:
            delays.append(delay)

        store = OpenSearchVectorStore(
            client,
            retry_delay=lambda: 0.1,
            sleep=record_sleep,
        )
        assert await store.healthcheck()
        assert client.cluster.calls == 2
        assert delays == [0.1]

    asyncio.run(scenario())


def test_opensearch_aborts_when_provider_returns_an_unauthorized_hit() -> None:
    async def scenario() -> None:
        client = FakeOpenSearchClient()
        store = OpenSearchVectorStore(client)
        specification = CollectionSpec(name="w10_002_opensearch_authorization")
        await store.create_or_validate_collection(specification)
        unauthorized = chunk("tenant-b")
        client.documents[unauthorized.chunk_id] = unauthorized.model_dump(mode="json")

        with pytest.raises(VectorStoreAuthorizationError):
            await store.search(
                specification,
                Query(text="policy"),
                vector(),
                auth(Role.READER),
            )

    asyncio.run(scenario())


@pytest.mark.aws
def test_live_opensearch_aws_contract_requires_separate_owner_approval() -> None:
    pytest.skip("live OpenSearch/AWS access is outside W2-001")
