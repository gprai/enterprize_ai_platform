"""Asynchronous provider-neutral VectorStore contract."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from .errors import VectorStoreValidationError
from .models import (
    APPROVED_EMBEDDING_DIMENSION,
    AuthContext,
    Chunk,
    CollectionSpec,
    Query,
    RetrievedChunk,
)

DEFAULT_OPERATION_TIMEOUT_SECONDS = 5.0
MAX_OPERATION_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_ATTEMPTS = 2


def validated_timeout(timeout_seconds: float | None) -> float:
    timeout = (
        DEFAULT_OPERATION_TIMEOUT_SECONDS
        if timeout_seconds is None
        else timeout_seconds
    )
    if not math.isfinite(timeout) or timeout <= 0 or timeout > MAX_OPERATION_TIMEOUT_SECONDS:
        raise VectorStoreValidationError
    return timeout


def validated_query_vector(vector: Sequence[float]) -> tuple[float, ...]:
    normalized = tuple(vector)
    if len(normalized) != APPROVED_EMBEDDING_DIMENSION:
        raise VectorStoreValidationError
    if not all(math.isfinite(value) for value in normalized):
        raise VectorStoreValidationError
    norm = math.sqrt(sum(value * value for value in normalized))
    if not math.isclose(norm, 1.0, rel_tol=1e-5, abs_tol=1e-5):
        raise VectorStoreValidationError
    return normalized


def require_approved_specification(specification: CollectionSpec) -> None:
    try:
        specification.assert_approved()
    except ValueError:
        raise VectorStoreValidationError from None


@runtime_checkable
class VectorStore(Protocol):
    """Stable contract implemented by fake, Qdrant and OpenSearch stores."""

    async def create_or_validate_collection(
        self,
        specification: CollectionSpec,
        *,
        timeout_seconds: float | None = None,
    ) -> None: ...

    async def upsert_chunks(
        self,
        specification: CollectionSpec,
        chunks: Sequence[Chunk],
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None: ...

    async def search(
        self,
        specification: CollectionSpec,
        query: Query,
        query_vector: Sequence[float],
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[RetrievedChunk, ...]: ...

    async def delete_by_document_id(
        self,
        specification: CollectionSpec,
        document_id: str,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None: ...

    async def delete_by_document_version(
        self,
        specification: CollectionSpec,
        document_id: str,
        document_version: str,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None: ...

    async def healthcheck(self, *, timeout_seconds: float | None = None) -> bool: ...
