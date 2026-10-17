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
    VectorStoreAuthorizationError,
    VectorStoreError,
    VectorStoreTimeoutError,
    VectorStoreUnavailableError,
    VectorStoreValidationError,
)
from ..hybrid import (
    APPROVED_HYBRID_POLICY,
    OPENSEARCH_CAPABILITIES,
    HybridRetrievalPolicy,
    RankedCandidate,
    RetrievalMode,
    build_retrieval_identity,
    fuse_ranked_candidates,
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
_RETRIEVAL_META_KEY = "enterprise_ai_retrieval_identity"
_RETRY_BASE_SECONDS = 0.1
_RETRY_JITTER_MILLISECONDS = 50
_AUTHORIZATION_MAPPING_FIELDS = (
    "tenant_id",
    "classification",
    "allowed_roles",
    "allowed_groups",
    "pii_status",
    "ingestion_status",
    "approved_exception",
)


def _retry_delay_seconds() -> float:
    return _RETRY_BASE_SECONDS + secrets.randbelow(_RETRY_JITTER_MILLISECONDS + 1) / 1000


class OpenSearchVectorStore:
    """Async OpenSearch implementation tested through an injected client."""

    def __init__(
        self,
        client: Any,
        *,
        retrieval_mode: RetrievalMode = RetrievalMode.VECTOR,
        hybrid_policy: HybridRetrievalPolicy = APPROVED_HYBRID_POLICY,
        max_attempts: int = DEFAULT_MAX_ATTEMPTS,
        retry_delay: Callable[[], float] = _retry_delay_seconds,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        if max_attempts < 1 or max_attempts > DEFAULT_MAX_ATTEMPTS:
            raise ValueError("max_attempts must be between 1 and 2")
        if (
            not isinstance(retrieval_mode, RetrievalMode)
            or not isinstance(hybrid_policy, HybridRetrievalPolicy)
            or hybrid_policy != APPROVED_HYBRID_POLICY
        ):
            raise VectorStoreValidationError
        OPENSEARCH_CAPABILITIES.require(retrieval_mode)
        self._client = client
        self._retrieval_mode = retrieval_mode
        self._hybrid_policy = hybrid_policy
        self._max_attempts = max_attempts
        self._retry_delay = retry_delay
        self._sleep = sleep

    @property
    def retrieval_mode(self) -> RetrievalMode:
        """Expose the immutable configured capability for composition checks."""

        return self._retrieval_mode

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

    def _mapping(self, specification: CollectionSpec) -> dict[str, Any]:
        retrieval_identity = build_retrieval_identity(
            specification,
            self._retrieval_mode,
            self._hybrid_policy,
        )
        text_mapping: dict[str, Any]
        if self._retrieval_mode is RetrievalMode.HYBRID:
            text_mapping = {
                "type": "text",
                "analyzer": self._hybrid_policy.lexical_analyzer,
                "search_analyzer": self._hybrid_policy.lexical_analyzer,
                "similarity": self._hybrid_policy.lexical_similarity,
            }
        else:
            text_mapping = {"type": "text", "index": False}
        return {
            "_meta": {
                _SPEC_META_KEY: specification.model_dump(mode="json"),
                _RETRIEVAL_META_KEY: retrieval_identity.model_dump(mode="json"),
            },
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
                "text": text_mapping,
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
        if not isinstance(response, dict):
            raise CollectionMismatchError
        index_entry = response.get(specification.name)
        if not isinstance(index_entry, dict):
            raise CollectionMismatchError
        index_mapping = index_entry.get("mappings")
        if not isinstance(index_mapping, dict):
            raise CollectionMismatchError
        expected = self._mapping(specification)
        if index_mapping.get("_meta") != expected["_meta"]:
            raise CollectionMismatchError
        properties = index_mapping.get("properties", {})
        if not isinstance(properties, dict):
            raise CollectionMismatchError
        expected_properties = expected["properties"]
        vector_mapping = properties.get("embedding", {})
        text_mapping = properties.get("text", {})
        if (
            vector_mapping.get("dimension") != specification.dimension
            or vector_mapping.get("method", {}).get("space_type") != "cosinesimil"
            or text_mapping != expected_properties["text"]
            or any(
                properties.get(field) != expected_properties[field]
                for field in _AUTHORIZATION_MAPPING_FIELDS
            )
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
                                    {"term": {"pii_status": PiiStatus.APPROVED_EXCEPTION.value}},
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
        if self._retrieval_mode is RetrievalMode.HYBRID:
            return await self._hybrid_search(
                specification=specification,
                query=query,
                vector=vector,
                auth_context=auth_context,
                policy=policy,
                timeout_seconds=timeout,
            )
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

    async def _hybrid_search(
        self,
        *,
        specification: CollectionSpec,
        query: Query,
        vector: tuple[float, ...],
        auth_context: AuthContext,
        policy: RetrievalPolicy,
        timeout_seconds: float,
    ) -> tuple[RetrievedChunk, ...]:
        candidate_limit = self._hybrid_policy.candidate_limit(query.top_k)
        filters = self._filters(policy)
        vector_body = {
            "size": candidate_limit,
            "query": {
                "bool": {
                    "filter": filters,
                    "must": [
                        {
                            "knn": {
                                "embedding": {
                                    "vector": list(vector),
                                    "k": candidate_limit,
                                }
                            }
                        }
                    ],
                }
            },
        }
        lexical_body = {
            "size": candidate_limit,
            "query": {
                "bool": {
                    "filter": filters,
                    "must": [{"match": {"text": {"query": query.text}}}],
                }
            },
        }
        vector_response, lexical_response = await self._execute_hybrid_channels(
            specification.name,
            vector_body,
            lexical_body,
            timeout_seconds,
        )
        vector_candidates = self._parse_hybrid_candidates(
            vector_response,
            auth_context,
            policy,
        )
        lexical_candidates = self._parse_hybrid_candidates(
            lexical_response,
            auth_context,
            policy,
        )
        return fuse_ranked_candidates(
            vector_candidates=vector_candidates,
            lexical_candidates=lexical_candidates,
            top_k=query.top_k,
            min_score=query.min_score,
            policy=self._hybrid_policy,
        )

    async def _execute_hybrid_channels(
        self,
        index_name: str,
        vector_body: dict[str, Any],
        lexical_body: dict[str, Any],
        timeout_seconds: float,
    ) -> tuple[Any, Any]:
        tasks = (
            asyncio.create_task(
                self._execute(
                    lambda: self._client.search(index=index_name, body=vector_body),
                    timeout_seconds,
                )
            ),
            asyncio.create_task(
                self._execute(
                    lambda: self._client.search(index=index_name, body=lexical_body),
                    timeout_seconds,
                )
            ),
        )
        try:
            async with asyncio.timeout(timeout_seconds):
                vector_response, lexical_response = await asyncio.gather(*tasks)
                return vector_response, lexical_response
        except TimeoutError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise VectorStoreTimeoutError from None
        except (Exception, asyncio.CancelledError):
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    @staticmethod
    def _parse_hybrid_candidates(
        response: Any,
        auth_context: AuthContext,
        policy: RetrievalPolicy,
    ) -> tuple[RankedCandidate, ...]:
        if not isinstance(response, dict):
            raise VectorStoreValidationError
        hits_container = response.get("hits")
        if not isinstance(hits_container, dict):
            raise VectorStoreValidationError
        hits = hits_container.get("hits")
        if not isinstance(hits, list):
            raise VectorStoreValidationError
        candidates: list[RankedCandidate] = []
        for hit in hits:
            if not isinstance(hit, dict):
                raise VectorStoreValidationError
            source = hit.get("_source")
            score = hit.get("_score")
            if (
                not isinstance(source, dict)
                or isinstance(score, bool)
                or not isinstance(score, (int, float))
            ):
                raise VectorStoreValidationError
            try:
                chunk = Chunk.model_validate_json(json.dumps(source))
            except ValidationError:
                raise VectorStoreValidationError from None
            if hit.get("_id") != chunk.chunk_id:
                raise VectorStoreValidationError
            if not is_retrieval_authorized(chunk, auth_context, now=policy.evaluated_at):
                raise VectorStoreAuthorizationError
            candidates.append(RankedCandidate(chunk=chunk, raw_score=float(score)))
        return tuple(candidates)

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
        await self._execute_destructive(
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
        await self._execute_destructive(
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
        response = await self._execute(
            lambda: self._client.count(
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
            ),
            timeout,
        )
        count = response.get("count")
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise VectorStoreUnavailableError
        return int(count)

    async def healthcheck(self, *, timeout_seconds: float | None = None) -> bool:
        timeout = validated_timeout(timeout_seconds)
        response = await self._execute(lambda: self._client.cluster.health(), timeout)
        return response.get("status") in {"green", "yellow"}
