"""Provider-neutral orchestration for authorized vector retrieval."""

from __future__ import annotations

import asyncio
from datetime import datetime

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

from .authorization import (
    build_retrieval_policy,
    is_retrieval_authorized,
    require_active_context,
)
from .errors import (
    RerankerError,
    RerankerInputLimitError,
    RerankerMalformedResponseError,
    RerankerSaturatedError,
    RerankerTimeoutError,
    RerankerUnavailableError,
    VectorStoreAuthorizationError,
    VectorStoreTimeoutError,
    VectorStoreValidationError,
)
from .models import AuthContext, CollectionSpec, Query, RetrievedChunk
from .reranking import (
    APPROVED_RERANKER_IDENTITY,
    APPROVED_RERANKING_POLICY,
    Reranker,
    RerankingPolicy,
    RerankRequest,
    RerankResponse,
    build_rerank_request,
)
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
        reranker: Reranker | None = None,
        reranking_policy: RerankingPolicy = APPROVED_RERANKING_POLICY,
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
        if reranker is not None and reranker.identity != APPROVED_RERANKER_IDENTITY:
            raise RerankerMalformedResponseError
        self._reranker = reranker
        self._reranking_policy = reranking_policy
        self._reranker_inflight = 0
        self._reranker_capacity_lock = asyncio.Lock()

    async def retrieve(
        self,
        query: Query,
        auth_context: AuthContext,
        *,
        timeout_seconds: float | None = None,
    ) -> tuple[RetrievedChunk, ...]:
        """Return authorized ranked chunks without changing provider state."""

        timeout = (
            self._timeout_seconds if timeout_seconds is None else validated_timeout(timeout_seconds)
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
                    policy = build_retrieval_policy(auth_context)
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
                if (
                    self._reranker is not None
                    and query.top_k > self._reranking_policy.maximum_top_k
                ):
                    raise RerankerInputLimitError
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
                        search_query = query
                        if self._reranker is not None:
                            search_query = Query(
                                text=query.text,
                                top_k=self._reranking_policy.maximum_candidates,
                                min_score=query.min_score,
                            )
                        results = await self._vector_store.search(
                            self._collection_spec,
                            search_query,
                            query_vector,
                            auth_context,
                            timeout_seconds=timeout,
                        )
                        vector_scope.finish(TelemetryOutcome.SUCCESS)
                    results = self._require_authorized_unique_results(
                        results,
                        auth_context,
                        policy.evaluated_at,
                    )
                    if self._reranker is not None and results:
                        results = await self._rerank_or_use_baseline(
                            query,
                            results,
                            auth_context,
                            policy.evaluated_at,
                        )
                self._telemetry.record_retrieval_results(len(results))
                retrieval_scope.finish(TelemetryOutcome.SUCCESS)
                return results
            except TimeoutError:
                retrieval_scope.finish(
                    TelemetryOutcome.TIMEOUT,
                    safe_error_code="vector_store_timeout",
                )
                raise VectorStoreTimeoutError from None

    @staticmethod
    def _require_authorized_unique_results(
        results: tuple[RetrievedChunk, ...],
        auth_context: AuthContext,
        evaluated_at: datetime,
    ) -> tuple[RetrievedChunk, ...]:
        identifiers: set[str] = set()
        for result in results:
            if result.chunk_id in identifiers:
                raise VectorStoreValidationError
            identifiers.add(result.chunk_id)
            if not is_retrieval_authorized(result, auth_context, now=evaluated_at):
                raise VectorStoreAuthorizationError
        return results

    async def _rerank_or_use_baseline(
        self,
        query: Query,
        baseline: tuple[RetrievedChunk, ...],
        auth_context: AuthContext,
        evaluated_at: datetime,
    ) -> tuple[RetrievedChunk, ...]:
        fallback = baseline[: query.top_k]
        request = build_rerank_request(
            query.text,
            tuple((chunk.chunk_id, chunk.text) for chunk in baseline),
            min(query.top_k, len(baseline)),
        )
        try:
            response = await self._execute_reranker(request)
            if response.identity != APPROVED_RERANKER_IDENTITY:
                raise RerankerMalformedResponseError
            expected_ids = {chunk.chunk_id for chunk in baseline}
            response_ids = tuple(result.chunk_id for result in response.results)
            if len(response_ids) != len(expected_ids) or set(response_ids) != expected_ids:
                raise RerankerMalformedResponseError
            by_id = {chunk.chunk_id: chunk for chunk in baseline}
            reranked = tuple(by_id[chunk_id] for chunk_id in response_ids[: query.top_k])
            return self._require_authorized_unique_results(
                reranked,
                auth_context,
                evaluated_at,
            )
        except RerankerError:
            return fallback

    async def _execute_reranker(self, request: RerankRequest) -> RerankResponse:
        if self._reranker is None:
            raise RerankerUnavailableError
        async with self._reranker_capacity_lock:
            if self._reranker_inflight >= self._reranking_policy.maximum_concurrent_calls:
                raise RerankerSaturatedError
            self._reranker_inflight += 1
        try:
            try:
                async with asyncio.timeout(self._reranking_policy.timeout_seconds):
                    return await self._reranker.rerank(
                        request,
                        timeout_seconds=self._reranking_policy.timeout_seconds,
                    )
            except RerankerError:
                raise
            except TimeoutError:
                raise RerankerTimeoutError from None
            except Exception:
                raise RerankerUnavailableError from None
        finally:
            async with self._reranker_capacity_lock:
                self._reranker_inflight -= 1
