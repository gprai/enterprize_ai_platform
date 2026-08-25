"""OpenSearch adapter boundary with no live AWS requirement."""

from __future__ import annotations

import asyncio
import json
import math
import secrets
from collections.abc import Awaitable, Callable, Sequence
from functools import partial
from typing import Any, TypeVar

from pydantic import ValidationError

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
_SPEC_META_KEY = "enterprise_ai_collection_spec"
_RETRY_BASE_SECONDS = 0.1
_RETRY_JITTER_MILLISECONDS = 50


def _retry_delay_seconds() -> float:
    return _RETRY_BASE_SECONDS + secrets.randbelow(_RETRY_JITTER_MILLISECONDS + 1) / 1000


class OpenSearchVectorStore:
    """Async OpenSearch implementation tested through an injected client."""

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

    @staticmethod
    def _mapping(specification: CollectionSpec) -> dict[str, Any]:
        return {
            "_meta": {_SPEC_META_KEY: specification.model_dump(mode="json")},
            "properties": {
                "embedding": {
                    "type": "knn_vector",
                    "dimension": specification.dimension,
                    "method": {
                        "name": "hnsw",
                        "engine": "lucene",
                        "space_type": "cosinesimil",
                    },
                },
                "tenant_id": {"type": "keyword"},
                "source_id": {"type": "keyword"},
                "media_type": {"type": "keyword"},
                "document_id": {"type": "keyword"},
                "document_version": {"type": "keyword"},
                "chunk_id": {"type": "keyword"},
                "classification": {"type": "keyword"},
                "allowed_roles": {"type": "keyword"},
                "allowed_groups": {"type": "keyword"},
                "data_owner": {"type": "keyword", "index": False},
                "content_hash": {"type": "keyword"},
                "pii_status": {"type": "keyword"},
                "ingestion_status": {"type": "keyword"},
                "approved_exception": {
                    "properties": {
                        "owner": {"type": "keyword", "index": False},
                        "rationale": {"type": "keyword", "index": False},
                        "expires_at": {"type": "date"},
                        "document_id": {"type": "keyword"},
                        "entity_types": {"type": "keyword"},
                    }
                },
                "chunk_index": {"type": "integer"},
                "text": {"type": "text", "index": False},
            },
        }

    async def _ensure_collection(
        self,
        specification: CollectionSpec,
        timeout_seconds: float,
    ) -> None:
        require_approved_specification(specification)
        exists = await self._execute(
            lambda: self._client.indices.exists(index=specification.name),
            timeout_seconds,
        )
        if not exists:
            raise CollectionMismatchError
        response = await self._execute(
            lambda: self._client.indices.get_mapping(index=specification.name),
            timeout_seconds,
        )
        index_mapping = response.get(specification.name, {}).get("mappings", {})
        expected = self._mapping(specification)
        if index_mapping.get("_meta") != expected["_meta"]:
            raise CollectionMismatchError
        vector_mapping = index_mapping.get("properties", {}).get("embedding", {})
        if (
            vector_mapping.get("dimension") != specification.dimension
            or vector_mapping.get("method", {}).get("space_type") != "cosinesimil"
        ):
            raise CollectionMismatchError

    @staticmethod
    def _filters(policy: RetrievalPolicy) -> list[dict[str, Any]]:
        acl_should: list[dict[str, Any]] = [
            {"terms": {"allowed_roles": [role.value for role in policy.roles]}}
        ]
        if policy.groups:
            acl_should.append({"terms": {"allowed_groups": list(policy.groups)}})
        return [
            {"term": {"tenant_id": policy.tenant_id}},
            {
                "terms": {
                    "classification": [
                        classification.value for classification in policy.classifications
                    ]
                }
            },
            {"term": {"ingestion_status": "INDEXED"}},
            {"bool": {"should": acl_should, "minimum_should_match": 1}},
            {
                "bool": {
                    "should": [
                        {
                            "terms": {
                                "pii_status": [
                                    PiiStatus.CLEAR.value,
                                    PiiStatus.REDACTED.value,
                                ]
                            }
                        },
                        {
                            "bool": {
                                "filter": [
                                    {
                                        "term": {
                                            "pii_status": PiiStatus.APPROVED_EXCEPTION.value
                                        }
                                    },
                                    {
                                        "range": {
                                            "approved_exception.expires_at": {
                                                "gt": policy.evaluated_at.isoformat()
                                            }
                                        }
                                    },
                                ]
                            }
                        },
                    ],
                    "minimum_should_match": 1,
                }
            },
        ]

    async def create_or_validate_collection(
        self,
        specification: CollectionSpec,
        *,
        timeout_seconds: float | None = None,
    ) -> None:
        timeout = validated_timeout(timeout_seconds)
        require_approved_specification(specification)
        exists = await self._execute(
            lambda: self._client.indices.exists(index=specification.name),
            timeout,
        )
        if not exists:
            await self._execute(
                lambda: self._client.indices.create(
                    index=specification.name,
                    body={
                        "settings": {"index": {"knn": True}},
                        "mappings": self._mapping(specification),
                    },
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
        for chunk in approved_chunks:
            body = chunk.model_dump(mode="json")
            body["embedding"] = list(chunk.embedding)
            operation: Callable[[], Awaitable[Any]] = partial(
                self._client.index,
                index=specification.name,
                id=chunk.chunk_id,
                body=body,
                refresh="wait_for",
            )
            await self._execute(
                operation,
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
        body = {
            "size": query.top_k,
            "min_score": query.min_score,
            "query": {
                "bool": {
                    "filter": self._filters(policy),
                    "must": [
                        {
                            "knn": {
                                "embedding": {
                                    "vector": list(vector),
                                    "k": query.top_k,
                                }
                            }
                        }
                    ],
                }
            },
        }
        response = await self._execute(
            lambda: self._client.search(index=specification.name, body=body),
            timeout,
        )
        results: list[RetrievedChunk] = []
        for hit in response.get("hits", {}).get("hits", []):
            source = dict(hit.get("_source", {}))
            try:
                chunk = Chunk.model_validate_json(json.dumps(source))
            except ValidationError:
                raise VectorStoreValidationError from None
            if is_retrieval_authorized(chunk, auth_context, now=policy.evaluated_at):
                results.append(
                    RetrievedChunk(**chunk.model_dump(), score=float(hit.get("_score", 0.0)))
                )
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
        await self._execute(
            lambda: self._client.delete_by_query(
                index=specification.name,
                body={
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"tenant_id": auth_context.tenant_id}},
                                {"term": {"document_id": document_id}},
                            ]
                        }
                    }
                },
                refresh=True,
                conflicts="proceed",
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
        await self._execute(
            lambda: self._client.delete_by_query(
                index=specification.name,
                body={
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"tenant_id": auth_context.tenant_id}},
                                {"term": {"document_id": document_id}},
                                {"term": {"document_version": document_version}},
                            ]
                        }
                    }
                },
                refresh=True,
                conflicts="proceed",
            ),
            timeout,
        )

    async def healthcheck(self, *, timeout_seconds: float | None = None) -> bool:
        timeout = validated_timeout(timeout_seconds)
        response = await self._execute(lambda: self._client.cluster.health(), timeout)
        return response.get("status") in {"green", "yellow"}
