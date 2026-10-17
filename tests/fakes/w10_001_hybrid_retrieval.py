"""Deterministic injected OpenSearch surface for W10-001 tests."""

from __future__ import annotations

import asyncio
from copy import deepcopy
from typing import Any

from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
    AuthContext,
    Chunk,
    Classification,
    IngestionStatus,
    PiiStatus,
    Role,
    deterministic_chunk_id,
)


def approved_vector() -> tuple[float, ...]:
    return (1.0, *([0.0] * (APPROVED_EMBEDDING_DIMENSION - 1)))


def make_chunk(
    chunk_index: int,
    *,
    tenant_id: str = "tenant-a",
    text: str | None = None,
    classification: Classification = Classification.INTERNAL,
) -> Chunk:
    content_hash = f"{chunk_index + 1:064x}"
    document_id = f"synthetic-policy-{chunk_index}"
    return Chunk(
        tenant_id=tenant_id,
        source_id=f"SOURCE-{chunk_index}",
        media_type="text/plain",
        document_id=document_id,
        document_version="v1",
        classification=classification,
        allowed_roles=frozenset({Role.READER}),
        allowed_groups=frozenset(),
        data_owner="synthetic-owner",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id=tenant_id,
            document_id=document_id,
            document_version="v1",
            content_hash=content_hash,
            chunk_index=chunk_index,
        ),
        chunk_index=chunk_index,
        text=text or f"Synthetic approved policy {chunk_index}",
        embedding=approved_vector(),
    )


def make_hit(chunk: Chunk, score: float) -> dict[str, Any]:
    return {
        "_id": chunk.chunk_id,
        "_score": score,
        "_source": chunk.model_dump(mode="json"),
    }


def reader_auth(
    tenant_id: str = "tenant-a",
    *,
    groups: frozenset[str] = frozenset(),
) -> AuthContext:
    return AuthContext(
        subject_id="synthetic-reader",
        tenant_id=tenant_id,
        roles=frozenset({Role.READER}),
        clearance=Classification.CONFIDENTIAL,
        groups=groups,
    )


class FakeHybridIndices:
    def __init__(self) -> None:
        self.created: dict[str, dict[str, Any]] = {}

    async def exists(self, *, index: str) -> bool:
        return index in self.created

    async def create(self, *, index: str, body: dict[str, Any]) -> dict[str, bool]:
        self.created[index] = deepcopy(body)
        return {"acknowledged": True}

    async def get_mapping(self, *, index: str) -> dict[str, Any]:
        return {index: {"mappings": deepcopy(self.created[index]["mappings"])}}


class FakeHybridCluster:
    async def health(self) -> dict[str, str]:
        return {"status": "green"}


class FakeHybridOpenSearchClient:
    """Return channel-specific results while recording bounded concurrency."""

    def __init__(
        self,
        *,
        vector_hits: list[dict[str, Any]] | None = None,
        lexical_hits: list[dict[str, Any]] | None = None,
    ) -> None:
        self.indices = FakeHybridIndices()
        self.cluster = FakeHybridCluster()
        self.vector_hits = vector_hits or []
        self.lexical_hits = lexical_hits or []
        self.search_calls: list[dict[str, Any]] = []
        self.failures_remaining = {"vector": 0, "lexical": 0}
        self.blocked_channels: set[str] = set()
        self.active_searches = 0
        self.maximum_active_searches = 0

    @staticmethod
    def channel(body: dict[str, Any]) -> str:
        must = body["query"]["bool"]["must"]
        return "vector" if "knn" in must[0] else "lexical"

    async def search(self, *, index: str, body: dict[str, Any]) -> dict[str, Any]:
        channel = self.channel(body)
        self.search_calls.append({"index": index, "channel": channel, "body": deepcopy(body)})
        self.active_searches += 1
        self.maximum_active_searches = max(
            self.maximum_active_searches,
            self.active_searches,
        )
        try:
            await asyncio.sleep(0)
            if channel in self.blocked_channels:
                await asyncio.Event().wait()
            if self.failures_remaining[channel]:
                self.failures_remaining[channel] -= 1
                raise RuntimeError("synthetic provider failure")
            hits = self.vector_hits if channel == "vector" else self.lexical_hits
            return {"hits": {"hits": deepcopy(hits)}}
        finally:
            self.active_searches -= 1
