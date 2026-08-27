"""Integration tests for guardrail ordering at the existing RAG boundary."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import cast

import pytest

from enterprise_ai_platform.guardrails import GuardrailInputError
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.models import ChatResponse, Usage
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.models import CitedAnswerResult
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


def _auth(*, expired: bool = False) -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
        expires_at=datetime(2000, 1, 1, tzinfo=UTC) if expired else None,
    )


def _chunk() -> RetrievedChunk:
    content_hash = "3" * 64
    chunk_id = deterministic_chunk_id(
        tenant_id="tenant-a",
        document_id="guardrail-contract",
        document_version="v1",
        content_hash=content_hash,
        chunk_index=0,
    )
    return RetrievedChunk(
        tenant_id="tenant-a",
        source_id="guardrail-source",
        media_type="text/plain",
        document_id="guardrail-contract",
        document_version="v1",
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        data_owner="owner-a",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=chunk_id,
        chunk_index=0,
        text="Deterministic policy surrounds generated output.",
        embedding=(1.0,) + (0.0,) * 383,
        score=0.9,
    )


class RecordingRetrieval:
    def __init__(self, chunks: tuple[RetrievedChunk, ...]) -> None:
        self.chunks = chunks
        self.queries: list[Query] = []

    async def retrieve(
        self,
        query: Query,
        auth_context: AuthContext,
    ) -> tuple[RetrievedChunk, ...]:
        self.queries.append(query)
        return self.chunks


def _service() -> tuple[RAGService, RecordingRetrieval, FakeLLMProvider]:
    chunk = _chunk()
    retrieval = RecordingRetrieval((chunk,))
    provider = FakeLLMProvider(
        [
            ChatResponse(
                text=json.dumps(
                    {
                        "answer": "Guardrails remain deterministic.",
                        "citations": [
                            {
                                "source_id": chunk.source_id,
                                "document_id": chunk.document_id,
                                "document_version": chunk.document_version,
                                "chunk_id": chunk.chunk_id,
                            }
                        ],
                    }
                ),
                usage=Usage(input_tokens=6, output_tokens=4, total_tokens=10),
            )
        ]
    )
    service = RAGService(
        retrieval_service=cast(RetrievalService, retrieval),
        llm_provider=provider,
        policy=RAGPolicy(
            top_k=5,
            min_score=0.5,
            minimum_qualifying_chunks=1,
            max_context_characters=12_000,
            max_output_tokens=512,
            prompt_version="w3-001.v1",
        ),
    )
    return service, retrieval, provider


def test_raw_string_is_normalized_before_existing_downstream_flow() -> None:
    service, retrieval, provider = _service()

    result = asyncio.run(service.answer(_auth(), "  governed question  "))

    assert isinstance(result, CitedAnswerResult)
    assert retrieval.queries == [
        Query(text="governed question", top_k=5, min_score=0.5)
    ]
    assert len(provider.requests) == 1


def test_existing_query_call_remains_compatible_with_policy_query_behavior() -> None:
    service, retrieval, _provider = _service()
    existing = Query(text="existing caller", top_k=17, min_score=0.1)

    asyncio.run(service.answer(_auth(), existing))

    assert retrieval.queries == [Query(text="existing caller", top_k=5, min_score=0.5)]


@pytest.mark.parametrize(
    ("query", "content_type"),
    [
        ("", "text/plain"),
        ("x" * 10_001, "text/plain"),
        ("valid", "application/json"),
    ],
)
def test_invalid_input_precedes_auth_retrieval_and_provider(
    query: str,
    content_type: str,
) -> None:
    service, retrieval, provider = _service()

    with pytest.raises(GuardrailInputError):
        asyncio.run(
            service.answer(
                _auth(expired=True),
                query,
                content_type=content_type,
            )
        )

    assert retrieval.queries == []
    assert provider.requests == []
