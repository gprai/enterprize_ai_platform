"""Feature acceptance tests for W3-001 provider-neutral cited RAG."""

from __future__ import annotations

import asyncio
import json
from typing import cast

from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.models import ChatResponse, Usage
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.models import AbstentionResult, CitedAnswerResult
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    IngestionStatus,
    PiiStatus,
    Query,
    RetrievedChunk,
    Role,
    deterministic_chunk_id,
)
from enterprise_ai_platform.retrieval.service import RetrievalService


def _chunk(score: float) -> RetrievedChunk:
    content_hash = "b" * 64
    chunk_id = deterministic_chunk_id(
        tenant_id="tenant-a",
        document_id="architecture-001",
        document_version="v1",
        content_hash=content_hash,
        chunk_index=0,
    )
    return RetrievedChunk(
        tenant_id="tenant-a",
        source_id="source-architecture",
        media_type="text/markdown",
        document_id="architecture-001",
        document_version="v1",
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        data_owner="owner-a",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=chunk_id,
        chunk_index=0,
        text="The provider boundary is selected explicitly.",
        embedding=(1.0,) + (0.0,) * 383,
        score=score,
    )


class FeatureRetrieval:
    def __init__(self, chunk: RetrievedChunk) -> None:
        self.chunk = chunk

    async def retrieve(
        self, query: Query, auth_context: AuthContext
    ) -> tuple[RetrievedChunk, ...]:
        return (self.chunk,)


def _policy() -> RAGPolicy:
    return RAGPolicy(
        top_k=5,
        min_score=0.50,
        minimum_qualifying_chunks=1,
        max_context_characters=12000,
        max_output_tokens=512,
        prompt_version="w3-001.v1",
    )


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def test_w3_001_returns_traceable_answer_or_pre_provider_abstention() -> None:
    qualifying = _chunk(0.90)
    generated = {
        "answer": "The provider boundary is selected explicitly.",
        "citations": [
            {
                "source_id": qualifying.source_id,
                "document_id": qualifying.document_id,
                "document_version": qualifying.document_version,
                "chunk_id": qualifying.chunk_id,
            }
        ],
    }
    provider = FakeLLMProvider(
        [
            ChatResponse(
                text=json.dumps(generated),
                usage=Usage(input_tokens=8, output_tokens=6, total_tokens=14),
            )
        ]
    )
    service = RAGService(
        retrieval_service=cast(RetrievalService, FeatureRetrieval(qualifying)),
        llm_provider=provider,
        policy=_policy(),
    )

    answer = asyncio.run(
        service.answer(_auth(), Query(text="How is the provider selected?"))
    )

    assert isinstance(answer, CitedAnswerResult)
    assert answer.prompt_version == "w3-001.v1"
    assert answer.answer.citations[0].chunk_id == qualifying.chunk_id

    weak_provider = FakeLLMProvider()
    weak_service = RAGService(
        retrieval_service=cast(RetrievalService, FeatureRetrieval(_chunk(0.49))),
        llm_provider=weak_provider,
        policy=_policy(),
    )
    abstention = asyncio.run(
        weak_service.answer(_auth(), Query(text="Synthetic weak query"))
    )

    assert abstention == AbstentionResult(
        reason="insufficient_evidence",
        prompt_version="w3-001.v1",
        usage=None,
    )
    assert weak_provider.requests == []
