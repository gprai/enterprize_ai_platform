"""In-process composition of API, authentication, and concrete local RAG."""

from __future__ import annotations

import json
from typing import cast

import pytest
from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.models import ChatResponse, Usage
from enterprise_ai_platform.rag.config import RAGPolicy
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
from tests.fakes.api import FakeAuthenticator, FakeReadinessProbe


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def _chunk(*, tenant_id: str = "tenant-a") -> RetrievedChunk:
    content_hash = "a" * 64
    document_id = "policy-001"
    version = "v1"
    return RetrievedChunk(
        tenant_id=tenant_id,
        source_id="source-001",
        media_type="text/plain",
        document_id=document_id,
        document_version=version,
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        data_owner="owner-a",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=deterministic_chunk_id(
            tenant_id=tenant_id,
            document_id=document_id,
            document_version=version,
            content_hash=content_hash,
            chunk_index=0,
        ),
        chunk_index=0,
        text="Approved deterministic evidence.",
        embedding=(1.0,) + (0.0,) * 383,
        score=0.9,
    )


class ControlledRetrieval:
    def __init__(self, chunks: tuple[RetrievedChunk, ...]) -> None:
        self.chunks = chunks
        self.calls = 0
        self.queries: list[Query] = []

    async def retrieve(
        self,
        query: Query,
        auth_context: AuthContext,
    ) -> tuple[RetrievedChunk, ...]:
        del auth_context
        self.calls += 1
        self.queries.append(query)
        return self.chunks


def _policy() -> RAGPolicy:
    return RAGPolicy(
        top_k=5,
        min_score=0.5,
        minimum_qualifying_chunks=1,
        max_context_characters=12_000,
        max_output_tokens=512,
        prompt_version="w3-001.v1",
    )


def _service(
    retrieval: ControlledRetrieval,
    provider: FakeLLMProvider,
) -> RAGService:
    return RAGService(
        retrieval_service=cast(RetrievalService, retrieval),
        llm_provider=provider,
        policy=_policy(),
    )


def test_injected_authenticator_composes_with_concrete_rag_and_local_fakes(
    api_settings: Settings,
) -> None:
    chunk = _chunk()
    retrieval = ControlledRetrieval((chunk,))
    provider = FakeLLMProvider(
        [
            ChatResponse(
                text=json.dumps(
                    {
                        "answer": "Governed composition works.",
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
                usage=Usage(input_tokens=4, output_tokens=3, total_tokens=7),
            )
        ]
    )
    authenticator = FakeAuthenticator(_auth())
    application = create_app(
        api_settings,
        authenticator=authenticator,
        rag_service=_service(retrieval, provider),
        readiness_probe=FakeReadinessProbe(),
    )

    response = TestClient(application).post(
        "/v1/query",
        json={"query": "Explain the approved boundary."},
    )

    assert response.status_code == 200
    assert response.json()["outcome"] == "answered"
    assert response.json()["answer"] == "Governed composition works."
    assert response.json()["citations"] == [
        {
            "source_id": chunk.source_id,
            "document_id": chunk.document_id,
            "document_version": chunk.document_version,
            "chunk_id": chunk.chunk_id,
            "label": None,
        }
    ]
    assert authenticator.calls == 1
    assert retrieval.calls == 1
    assert len(provider.requests) == 1
    assert retrieval.queries == [
        Query(
            text="Explain the approved boundary.",
            top_k=5,
            min_score=0.5,
        )
    ]


def test_authenticated_caller_with_no_authorized_evidence_gets_safe_abstention(
    api_settings: Settings,
) -> None:
    retrieval = ControlledRetrieval((_chunk(tenant_id="tenant-b"),))
    provider = FakeLLMProvider()
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=_service(retrieval, provider),
        readiness_probe=FakeReadinessProbe(),
    )

    response = TestClient(application).post(
        "/v1/query",
        json={"query": "Cross-tenant request"},
    )

    assert response.status_code == 200
    assert response.json()["outcome"] == "abstained"
    assert response.json()["reason"] == "no_authorized_evidence"
    assert "answer" not in response.json()
    assert "citations" not in response.json()
    assert retrieval.calls == 1
    assert provider.requests == []


@pytest.mark.parametrize("query", ["", "x" * 10_001])
def test_existing_logical_query_guardrail_stops_before_retrieval(
    api_settings: Settings,
    query: str,
) -> None:
    retrieval = ControlledRetrieval((_chunk(),))
    provider = FakeLLMProvider()
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=_service(retrieval, provider),
        readiness_probe=FakeReadinessProbe(),
    )

    response = TestClient(application).post(
        "/v1/query",
        json={"query": query},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "guardrail_input_invalid"
    assert retrieval.calls == 0
    assert provider.requests == []
