"""Deterministic in-memory VectorStore used by always-on contract tests."""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from dataclasses import dataclass, field

from ..authorization import (
    build_retrieval_policy,
    is_retrieval_authorized,
    require_delete_authorized,
    require_upsert_authorized,
)
from ..errors import (
    CollectionMismatchError,
    VectorStoreUnavailableError,
    VectorStoreValidationError,
)
from ..models import AuthContext, Chunk, CollectionSpec, Query, RetrievedChunk
from ..vector_store import (
    require_approved_specification,
    validated_query_vector,
    validated_timeout,
)


@dataclass(slots=True)
class _FakeCollection:
    specification: CollectionSpec
    chunks: dict[str, Chunk] = field(default_factory=dict)


class InMemoryVectorStore:
    """Predictable fake with the same security and collection rules as real adapters."""

    def __init__(self, *, available: bool = True) -> None:
        self._available = available
        self._collections: dict[str, _FakeCollection] = {}
        self._lock = asyncio.Lock()

    def set_available(self, available: bool) -> None:
        """Deterministically inject availability failures in automated tests."""

        self._available = available

    def _require_available(self) -> None:
        if not self._available:
            raise VectorStoreUnavailableError

    def _collection(self, specification: CollectionSpec) -> _FakeCollection:
        require_approved_specification(specification)
        collection = self._collections.get(specification.name)
        if collection is None or collection.specification != specification:
            raise CollectionMismatchError
        return collection

    async def create_or_validate_collection(
        self,
        specification: CollectionSpec,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        validated_timeout(timeout_seconds)
        require_approved_specification(specification)
        self._require_available()
        async with self._lock:
            existing = self._collections.get(specification.name)
            if existing is None:
                self._collections[specification.name] = _FakeCollection(specification)
            elif existing.specification != specification:
                raise CollectionMismatchError

    async def upsert_chunks(
        self,
        specification: CollectionSpec,
        chunks: Sequence[Chunk],
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        validated_timeout(timeout_seconds)
        approved_chunks = require_upsert_authorized(chunks, auth_context)
        self._require_available()
        async with self._lock:
            collection = self._collection(specification)
            for chunk in approved_chunks:
                collection.chunks[chunk.chunk_id] = chunk

    async def search(
        self,
        specification: CollectionSpec,
        query: Query,
        query_vector: Sequence[float],
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[RetrievedChunk, ...]:
        validated_timeout(timeout_seconds)
        vector = validated_query_vector(query_vector)
        policy = build_retrieval_policy(auth_context)
        self._require_available()
        async with self._lock:
            collection = self._collection(specification)
            candidates = (
                chunk
                for chunk in collection.chunks.values()
                if chunk.tenant_id == policy.tenant_id
                and chunk.classification in policy.classifications
                and chunk.pii_status in policy.allowed_pii_statuses
                and (
                    bool(chunk.allowed_roles.intersection(policy.roles))
                    or bool(chunk.allowed_groups.intersection(policy.groups))
                )
            )
            scored = sorted(
                (
                    (
                        sum(
                            left * right
                            for left, right in zip(chunk.embedding, vector, strict=True)
                        ),
                        chunk,
                    )
                    for chunk in candidates
                ),
                key=lambda item: (-item[0], item[1].chunk_id),
            )
            results: list[RetrievedChunk] = []
            for score, chunk in scored:
                if score < query.min_score:
                    continue
                if not is_retrieval_authorized(
                    chunk,
                    auth_context,
                    now=policy.evaluated_at,
                ):
                    continue
                results.append(
                    RetrievedChunk(**chunk.model_dump(), score=max(-1.0, min(1.0, score)))
                )
                if len(results) == query.top_k:
                    break
            return tuple(results)

    async def delete_by_document_id(
        self,
        specification: CollectionSpec,
        document_id: str,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        validated_timeout(timeout_seconds)
        require_delete_authorized(auth_context)
        if not document_id.strip():
            raise VectorStoreValidationError
        self._require_available()
        async with self._lock:
            collection = self._collection(specification)
            delete_ids = [
                chunk_id
                for chunk_id, chunk in collection.chunks.items()
                if chunk.tenant_id == auth_context.tenant_id
                and chunk.document_id == document_id
            ]
            for chunk_id in delete_ids:
                del collection.chunks[chunk_id]

    async def delete_by_document_version(
        self,
        specification: CollectionSpec,
        document_id: str,
        document_version: str,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        validated_timeout(timeout_seconds)
        require_delete_authorized(auth_context)
        if not document_id.strip() or not document_version.strip():
            raise VectorStoreValidationError
        self._require_available()
        async with self._lock:
            collection = self._collection(specification)
            delete_ids = [
                chunk_id
                for chunk_id, chunk in collection.chunks.items()
                if chunk.tenant_id == auth_context.tenant_id
                and chunk.document_id == document_id
                and chunk.document_version == document_version
            ]
            for chunk_id in delete_ids:
                del collection.chunks[chunk_id]

    async def healthcheck(self, *, timeout_seconds: float | None = None) -> bool:
        validated_timeout(timeout_seconds)
        return self._available
