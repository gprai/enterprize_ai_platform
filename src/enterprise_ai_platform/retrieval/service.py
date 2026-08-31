"""Provider-neutral orchestration for authorized vector retrieval."""

from __future__ import annotations

import asyncio

from enterprise_ai_platform.embeddings.base import (
    Embedder,
    EmbeddingContract,
    assert_embedding_contract,
)
from enterprise_ai_platform.telemetry.models import (
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import (
    NullTelemetryRuntime,
    TelemetryRuntime,
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
        telemetry: TelemetryRuntime | None = None,
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
        self._telemetry = telemetry or NullTelemetryRuntime()

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
        with self._telemetry.start_scope(
            TelemetryStage.RETRIEVAL,
            TelemetryOperation.RETRIEVE,
        ) as retrieval_scope:
            with self._telemetry.start_scope(
                TelemetryStage.AUTHORIZATION,
                TelemetryOperation.AUTHORIZE,
            ) as authorization_scope:
                try:
                    require_active_context(auth_context)
                    build_retrieval_policy(auth_context)
                except Exception:
                    authorization_scope.finish(
                        TelemetryOutcome.DENIED,
                        terminal_reason="authorization_denied",
                        safe_error_code="vector_store_authorization_denied",
                    )
                    self._telemetry.emit_event(
                        TelemetryEventName.SECURITY_DECISION,
                        SafeTelemetryAttributes(
                            stage=TelemetryStage.AUTHORIZATION,
                            operation=TelemetryOperation.AUTHORIZE,
                            outcome=TelemetryOutcome.DENIED,
                            terminal_reason="authorization_denied",
                            safe_error_code="vector_store_authorization_denied",
                        ),
                    )
                    raise
                authorization_scope.finish(TelemetryOutcome.SUCCESS)
            try:
                async with asyncio.timeout(timeout):
                    with self._telemetry.start_scope(
                        TelemetryStage.EMBEDDING,
                        TelemetryOperation.EMBED_QUERY,
                    ) as embedding_scope:
                        query_vector = await self._embedder.embed_query(query.text)
                        embedding_scope.finish(TelemetryOutcome.SUCCESS)
                    with self._telemetry.start_scope(
                        TelemetryStage.VECTOR_SEARCH,
                        TelemetryOperation.SEARCH,
                    ) as vector_scope:
                        results = await self._vector_store.search(
                            self._collection_spec,
                            query,
                            query_vector,
                            auth_context,
                            timeout_seconds=timeout,
                        )
                        vector_scope.finish(TelemetryOutcome.SUCCESS)
                self._telemetry.record_retrieval_results(len(results))
                retrieval_scope.finish(TelemetryOutcome.SUCCESS)
                return results
            except TimeoutError:
                retrieval_scope.finish(
                    TelemetryOutcome.TIMEOUT,
                    safe_error_code="vector_store_timeout",
                )
                raise VectorStoreTimeoutError from None
