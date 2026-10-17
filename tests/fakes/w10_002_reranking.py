"""Deterministic W10-002 fixtures with no network or model dependencies."""

from __future__ import annotations

import asyncio

from enterprise_ai_platform.retrieval.adapters.fake import InMemoryVectorStore
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Query,
    RetrievedChunk,
    Role,
)
from enterprise_ai_platform.retrieval.reranking import (
    APPROVED_RERANKER_IDENTITY,
    RerankRequest,
    RerankResponse,
    RerankScore,
)
from tests.fakes.w10_001_hybrid_retrieval import make_chunk


def reader_auth(tenant_id: str = "tenant-a") -> AuthContext:
    return AuthContext(
        subject_id="synthetic-w10-002-reader",
        tenant_id=tenant_id,
        roles=frozenset({Role.READER}),
        clearance=Classification.CONFIDENTIAL,
    )


def retrieved_chunks(*texts: str) -> tuple[RetrievedChunk, ...]:
    return tuple(
        RetrievedChunk(**make_chunk(index, text=text).model_dump(), score=1.0 - index / 100)
        for index, text in enumerate(texts)
    )


class StaticVectorStore(InMemoryVectorStore):
    """Return exact injected candidates while recording the candidate budget."""

    def __init__(self, results: tuple[RetrievedChunk, ...]) -> None:
        super().__init__()
        self.results = results
        self.queries: list[Query] = []

    async def search(
        self,
        specification,
        query,
        query_vector,
        auth_context,
        *,
        timeout_seconds=None,
    ):  # type: ignore[no-untyped-def]
        del specification, query_vector, auth_context, timeout_seconds
        self.queries.append(query)
        return self.results[: query.top_k]


class RecordingReranker:
    """Injected reranker capable of deterministic ordering, failure, or blocking."""

    identity = APPROVED_RERANKER_IDENTITY

    def __init__(
        self,
        *,
        order: tuple[str, ...] | None = None,
        failure: Exception | None = None,
        blocked: bool = False,
    ) -> None:
        self.order = order
        self.failure = failure
        self.calls: list[RerankRequest] = []
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        if not blocked:
            self.release.set()

    async def rerank(
        self,
        request: RerankRequest,
        *,
        timeout_seconds: float,
    ) -> RerankResponse:
        del timeout_seconds
        self.calls.append(request)
        self.started.set()
        await self.release.wait()
        if self.failure is not None:
            raise self.failure
        order = self.order or tuple(candidate.chunk_id for candidate in request.candidates)
        return RerankResponse(
            identity=self.identity,
            results=tuple(
                RerankScore(chunk_id=chunk_id, score=1.0 - index / 100)
                for index, chunk_id in enumerate(order)
            ),
        )
