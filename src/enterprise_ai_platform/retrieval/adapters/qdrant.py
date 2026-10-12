"""Qdrant adapter with collection validation and authorization filters."""

from __future__ import annotations

import asyncio
import json
import math
import secrets
import uuid
from collections.abc import Awaitable, Callable, Sequence
from typing import Any, TypeVar

from pydantic import ValidationError
from qdrant_client.http import models as qmodels

from ..authorization import (
    RetrievalPolicy,
    build_retrieval_policy,
    is_retrieval_authorized,
    require_delete_authorized,
    require_upsert_authorized,
)
from ..errors import (
    CollectionMismatchError,
    VectorStoreError,
    VectorStoreTimeoutError,
    VectorStoreUnavailableError,
    VectorStoreValidationError,
)
from ..models import AuthContext, Chunk, CollectionSpec, PiiStatus, Query, RetrievedChunk
from ..vector_store import (
    DEFAULT_MAX_ATTEMPTS,
    require_approved_specification,
    validated_query_vector,
    validated_timeout,
)

_T = TypeVar("_T")
_SPEC_POINT_ID = "00000000-0000-5000-8000-000000000001"
_RECORD_TYPE = "enterprise_ai_record_type"
_CHUNK_RECORD = "chunk"
_SPEC_RECORD = "collection_spec"
_RETRY_BASE_SECONDS = 0.1
_RETRY_JITTER_MILLISECONDS = 50


def _retry_delay_seconds() -> float:
    return _RETRY_BASE_SECONDS + secrets.randbelow(_RETRY_JITTER_MILLISECONDS + 1) / 1000


def _qdrant_point_id(chunk_id: str) -> str:
    return str(uuid.UUID(bytes=bytes.fromhex(chunk_id)[:16], version=5))


class QdrantVectorStore:
    """Async Qdrant implementation that never returns Qdrant SDK objects."""

    def __init__(
        self,
        client: Any,
        *,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        retry_delay: Callable[[], float] = _retry_delay_seconds,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if max_attempts < 1 or max_attempts > DEFAULT_MAX_ATTEMPTS:
            raise ValueError("max_attempts must be between 1 and 2")
        self._client = client
        self._max_attempts = max_attempts
        self._retry_delay = retry_delay
        self._sleep = sleep

    async def _wait_before_retry(self, deadline: float) -> None:
        delay = self._retry_delay()
        if not math.isfinite(delay) or not 0.1 <= delay <= 0.15:
            raise VectorStoreValidationError
        if asyncio.get_running_loop().time() + delay >= deadline:
            raise VectorStoreTimeoutError
        await self._sleep(delay)

    async def _execute(
        self,
        operation: Callable[[], Awaitable[_T]],
        timeout_seconds: float,
    ) -> _T:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        for attempt in range(self._max_attempts):
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise VectorStoreTimeoutError
            attempts_left = self._max_attempts - attempt
            try:
                return await asyncio.wait_for(operation(), timeout=remaining / attempts_left)
            except VectorStoreError:
                raise
            except TimeoutError:
                if attempt + 1 == self._max_attempts:
                    raise VectorStoreTimeoutError from None
                await self._wait_before_retry(deadline)
            except Exception:
                if attempt + 1 == self._max_attempts:
                    raise VectorStoreUnavailableError from None
                await self._wait_before_retry(deadline)
        raise VectorStoreUnavailableError

    async def _execute_destructive(
        self,
        operation: Callable[[], Awaitable[_T]],
        timeout_seconds: float,
    ) -> _T:
        """Execute a mutation once; destructive retries require a new approval."""

        try:
            return await asyncio.wait_for(operation(), timeout=timeout_seconds)
        except VectorStoreError:
            raise
        except TimeoutError:
            raise VectorStoreTimeoutError from None
        except Exception:
            raise VectorStoreUnavailableError from None

    @staticmethod
    def _spec_payload(specification: CollectionSpec) -> dict[str, Any]:
        return {
            _RECORD_TYPE: _SPEC_RECORD,
            "specification": specification.model_dump(mode="json"),
        }

    async def _ensure_collection(
        self,
        specification: CollectionSpec,
        timeout_seconds: float,
    ) -> None:
        require_approved_specification(specification)
        exists = await self._execute(
            lambda: self._client.collection_exists(specification.name),
            timeout_seconds,
        )
        if not exists:
            raise CollectionMismatchError
        info = await self._execute(
            lambda: self._client.get_collection(specification.name),
            timeout_seconds,
        )
        vectors = getattr(getattr(info.config, "params", None), "vectors", None)
        dimension = getattr(vectors, "size", None)
        distance = str(getattr(vectors, "distance", "")).casefold()
        if dimension != specification.dimension or "cosine" not in distance:
            raise CollectionMismatchError
        records = await self._execute(
            lambda: self._client.retrieve(
                collection_name=specification.name,
                ids=[_SPEC_POINT_ID],
                with_payload=True,
                with_vectors=False,
            ),
            timeout_seconds,
        )
        if len(records) != 1 or records[0].payload != self._spec_payload(specification):
            raise CollectionMismatchError

    @staticmethod
    def _query_filter(policy: RetrievalPolicy) -> qmodels.Filter:
        acl_conditions: list[Any] = [
            qmodels.FieldCondition(
                key="allowed_roles",
                match=qmodels.MatchAny(any=[role.value for role in policy.roles]),
            )
        ]
        if policy.groups:
            acl_conditions.append(
                qmodels.FieldCondition(
                    key="allowed_groups",
                    match=qmodels.MatchAny(any=list(policy.groups)),
                )
            )
        pii_condition = qmodels.Filter(
            should=[
                qmodels.FieldCondition(
                    key="pii_status",
                    match=qmodels.MatchAny(any=[PiiStatus.CLEAR.value, PiiStatus.REDACTED.value]),
                ),
                qmodels.Filter(
                    must=[
                        qmodels.FieldCondition(
                            key="pii_status",
                            match=qmodels.MatchValue(value=PiiStatus.APPROVED_EXCEPTION.value),
                        ),
                        qmodels.FieldCondition(
                            key="approved_exception.expires_at",
                            range=qmodels.DatetimeRange(gt=policy.evaluated_at),
                        ),
                    ]
                ),
            ]
        )
        return qmodels.Filter(
            must=[
                qmodels.FieldCondition(
                    key=_RECORD_TYPE,
                    match=qmodels.MatchValue(value=_CHUNK_RECORD),
                ),
                qmodels.FieldCondition(
                    key="tenant_id",
                    match=qmodels.MatchValue(value=policy.tenant_id),
                ),
                qmodels.FieldCondition(
                    key="classification",
                    match=qmodels.MatchAny(
                        any=[classification.value for classification in policy.classifications]
                    ),
                ),
                qmodels.FieldCondition(
                    key="ingestion_status",
                    match=qmodels.MatchValue(value="INDEXED"),
                ),
                qmodels.Filter(should=acl_conditions),
                pii_condition,
            ]
        )

    async def create_or_validate_collection(
        self,
        specification: CollectionSpec,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        timeout = validated_timeout(timeout_seconds)
        require_approved_specification(specification)
        exists = await self._execute(
            lambda: self._client.collection_exists(specification.name),
            timeout,
        )
        if not exists:
            await self._execute(
                lambda: self._client.create_collection(
                    collection_name=specification.name,
                    vectors_config=qmodels.VectorParams(
                        size=specification.dimension,
                        distance=qmodels.Distance.COSINE,
                    ),
                ),
                timeout,
            )
            await self._execute(
                lambda: self._client.upsert(
                    collection_name=specification.name,
                    points=[
                        qmodels.PointStruct(
                            id=_SPEC_POINT_ID,
                            vector=[1.0] + [0.0] * (specification.dimension - 1),
                            payload=self._spec_payload(specification),
                        )
                    ],
                    wait=True,
                ),
                timeout,
            )
        await self._ensure_collection(specification, timeout)

    async def upsert_chunks(
        self,
        specification: CollectionSpec,
        chunks: Sequence[Chunk],
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        timeout = validated_timeout(timeout_seconds)
        approved_chunks = require_upsert_authorized(chunks, auth_context)
        await self._ensure_collection(specification, timeout)
        points = []
        for chunk in approved_chunks:
            payload = chunk.model_dump(mode="json", exclude={"embedding"})
            payload[_RECORD_TYPE] = _CHUNK_RECORD
            points.append(
                qmodels.PointStruct(
                    id=_qdrant_point_id(chunk.chunk_id),
                    vector=list(chunk.embedding),
                    payload=payload,
                )
            )
        await self._execute(
            lambda: self._client.upsert(
                collection_name=specification.name,
                points=points,
                wait=True,
            ),
            timeout,
        )

    async def search(
        self,
        specification: CollectionSpec,
        query: Query,
        query_vector: Sequence[float],
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[RetrievedChunk, ...]:
        timeout = validated_timeout(timeout_seconds)
        vector = validated_query_vector(query_vector)
        policy = build_retrieval_policy(auth_context)
        await self._ensure_collection(specification, timeout)
        response = await self._execute(
            lambda: self._client.query_points(
                collection_name=specification.name,
                query=list(vector),
                query_filter=self._query_filter(policy),
                limit=query.top_k,
                score_threshold=query.min_score,
                with_payload=True,
                with_vectors=True,
            ),
            timeout,
        )
        results: list[RetrievedChunk] = []
        for point in response.points:
            payload = dict(point.payload or {})
            payload.pop(_RECORD_TYPE, None)
            vector_payload = point.vector
            if not isinstance(vector_payload, list):
                raise VectorStoreValidationError
            try:
                chunk = Chunk.model_validate_json(
                    json.dumps({**payload, "embedding": vector_payload})
                )
            except ValidationError:
                raise VectorStoreValidationError from None
            if is_retrieval_authorized(chunk, auth_context, now=policy.evaluated_at):
                results.append(RetrievedChunk(**chunk.model_dump(), score=float(point.score)))
        return tuple(results)

    async def delete_by_document_id(
        self,
        specification: CollectionSpec,
        document_id: str,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        timeout = validated_timeout(timeout_seconds)
        require_delete_authorized(auth_context)
        if not document_id.strip():
            raise VectorStoreValidationError
        await self._ensure_collection(specification, timeout)
        delete_filter = qmodels.Filter(
            must=[
                qmodels.FieldCondition(
                    key=_RECORD_TYPE,
                    match=qmodels.MatchValue(value=_CHUNK_RECORD),
                ),
                qmodels.FieldCondition(
                    key="tenant_id",
                    match=qmodels.MatchValue(value=auth_context.tenant_id),
                ),
                qmodels.FieldCondition(
                    key="document_id",
                    match=qmodels.MatchValue(value=document_id),
                ),
            ]
        )
        await self._execute_destructive(
            lambda: self._client.delete(
                collection_name=specification.name,
                points_selector=qmodels.FilterSelector(filter=delete_filter),
                wait=True,
            ),
            timeout,
        )

    async def delete_by_document_version(
        self,
        specification: CollectionSpec,
        document_id: str,
        document_version: str,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        timeout = validated_timeout(timeout_seconds)
        require_delete_authorized(auth_context)
        if not document_id.strip() or not document_version.strip():
            raise VectorStoreValidationError
        await self._ensure_collection(specification, timeout)
        delete_filter = qmodels.Filter(
            must=[
                qmodels.FieldCondition(
                    key=_RECORD_TYPE,
                    match=qmodels.MatchValue(value=_CHUNK_RECORD),
                ),
                qmodels.FieldCondition(
                    key="tenant_id",
                    match=qmodels.MatchValue(value=auth_context.tenant_id),
                ),
                qmodels.FieldCondition(
                    key="document_id",
                    match=qmodels.MatchValue(value=document_id),
                ),
                qmodels.FieldCondition(
                    key="document_version",
                    match=qmodels.MatchValue(value=document_version),
                ),
            ]
        )
        await self._execute_destructive(
            lambda: self._client.delete(
                collection_name=specification.name,
                points_selector=qmodels.FilterSelector(filter=delete_filter),
                wait=True,
            ),
            timeout,
        )

    async def count_by_document_version(
        self,
        specification: CollectionSpec,
        document_id: str,
        document_version: str,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> int:
        timeout = validated_timeout(timeout_seconds)
        require_delete_authorized(auth_context)
        if not document_id.strip() or not document_version.strip():
            raise VectorStoreValidationError
        await self._ensure_collection(specification, timeout)
        count_filter = qmodels.Filter(
            must=[
                qmodels.FieldCondition(
                    key=_RECORD_TYPE,
                    match=qmodels.MatchValue(value=_CHUNK_RECORD),
                ),
                qmodels.FieldCondition(
                    key="tenant_id",
                    match=qmodels.MatchValue(value=auth_context.tenant_id),
                ),
                qmodels.FieldCondition(
                    key="document_id",
                    match=qmodels.MatchValue(value=document_id),
                ),
                qmodels.FieldCondition(
                    key="document_version",
                    match=qmodels.MatchValue(value=document_version),
                ),
            ]
        )
        response = await self._execute(
            lambda: self._client.count(
                collection_name=specification.name,
                count_filter=count_filter,
                exact=True,
            ),
            timeout,
        )
        count = getattr(response, "count", None)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise VectorStoreUnavailableError
        return count

    async def healthcheck(self, *, timeout_seconds: float | None = None) -> bool:
        timeout = validated_timeout(timeout_seconds)
        await self._execute(lambda: self._client.get_collections(), timeout)
        return True
