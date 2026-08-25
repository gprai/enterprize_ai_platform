"""Provider-neutral orchestration for authorized vector retrieval."""

from __future__ import annotations

import asyncio

from enterprise_ai_platform.embeddings.base import (
    Embedder,
    EmbeddingContract,
    assert_embedding_contract,
)

from .authorization import build_retrieval_policy, require_active_context
from .errors import VectorStoreTimeoutError
from .models import AuthContext, CollectionSpec, Query, RetrievedChunk
from .vector_store import (
    VectorStore,
    require_approved_specification,
    validated_timeout,
)


class RetrievalService:
    """Compose approved embedding and vector-store contracts without mutation."""

    def __init__(
        self,
        *,
        embedder: Embedder,
        vector_store: VectorStore,
        collection_spec: CollectionSpec,
        timeout_seconds: float | None = None,
    ) -> None:
        require_approved_specification(collection_spec)
        assert_embedding_contract(
            embedder,
            EmbeddingContract(
                model_id=collection_spec.embedding_model_id,
                model_revision=collection_spec.embedding_revision,
                dimension=collection_spec.dimension,
                normalized=collection_spec.normalized,
                metric=collection_spec.metric.value,
            ),
        )
        self._embedder = embedder
        self._vector_store = vector_store
        self._collection_spec = collection_spec
        self._timeout_seconds = validated_timeout(timeout_seconds)

    async def retrieve(
        self,
        query: Query,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[RetrievedChunk, ...]:
        """Return authorized ranked chunks without changing provider state."""

        timeout = (
            self._timeout_seconds
            if timeout_seconds is None
            else validated_timeout(timeout_seconds)
        )
        require_active_context(auth_context)
        build_retrieval_policy(auth_context)
        try:
            async with asyncio.timeout(timeout):
                query_vector = await self._embedder.embed_query(query.text)
                return await self._vector_store.search(
                    self._collection_spec,
                    query,
                    query_vector,
                    auth_context,
                    timeout_seconds=timeout,
                )
        except TimeoutError:
            raise VectorStoreTimeoutError from None
