"""Unit tests for authorization-first cited-RAG decisions and failure mapping."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from typing import cast

import pytest

from enterprise_ai_platform.guardrails import GuardrailInputError
from enterprise_ai_platform.llm.errors import (
    LLMAuthenticationError,
    LLMAuthorizationError,
    LLMError,
    LLMMalformedResponseError,
    LLMThrottlingError,
    LLMTimeoutError,
    LLMUnavailableError,
)
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.models import ChatResponse, ToolCall, Usage
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.errors import RAGOutputValidationError
from enterprise_ai_platform.rag.models import AbstentionResult, CitedAnswerResult
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.errors import VectorStoreAuthorizationError
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


def _policy() -> RAGPolicy:
    return RAGPolicy(
        top_k=5,
        min_score=0.50,
        minimum_qualifying_chunks=1,
        max_context_characters=12000,
        max_output_tokens=512,
        prompt_version="w3-001.v1",
    )


def _w10_policy() -> RAGPolicy:
    return RAGPolicy(
        top_k=5,
        min_score=0.50,
        minimum_qualifying_chunks=1,
        max_context_characters=12000,
        max_output_tokens=512,
        prompt_version="w10-003.extractive.v2",
    )


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def _chunk(
    *,
    tenant_id: str = "tenant-a",
    source_id: str = "source-001",
    document_id: str = "policy-001",
    document_version: str = "v1",
    chunk_index: int = 0,
    score: float = 0.90,
    text: str = "Approved synthetic evidence.",
) -> RetrievedChunk:
    content_hash = "a" * 64
    chunk_id = deterministic_chunk_id(
        tenant_id=tenant_id,
        document_id=document_id,
        document_version=document_version,
        content_hash=content_hash,
        chunk_index=chunk_index,
    )
    return RetrievedChunk(
        tenant_id=tenant_id,
        source_id=source_id,
        media_type="text/plain",
        document_id=document_id,
        document_version=document_version,
        classification=Classification.INTERNAL,
        allowed_roles=frozenset({Role.READER}),
        data_owner="owner-a",
        content_hash=content_hash,
        pii_status=PiiStatus.CLEAR,
        ingestion_status=IngestionStatus.INDEXED,
        chunk_id=chunk_id,
        chunk_index=chunk_index,
        text=text,
        embedding=(1.0,) + (0.0,) * 383,
        score=score,
    )


class StubRetrieval:
    def __init__(self, chunks: object) -> None:
        self.chunks = chunks
        self.calls = 0

    async def retrieve(self, query: Query, auth_context: AuthContext) -> object:
        self.calls += 1
        return self.chunks


class FailingRetrieval:
    async def retrieve(self, query: Query, auth_context: AuthContext) -> object:
        raise VectorStoreAuthorizationError


def _citation(chunk: RetrievedChunk) -> dict[str, str]:
    return {
        "source_id": chunk.source_id,
        "document_id": chunk.document_id,
        "document_version": chunk.document_version,
        "chunk_id": chunk.chunk_id,
    }


def _response(citations: object, *, answer: str = "Governed answer.") -> ChatResponse:
    return ChatResponse(
        text=json.dumps({"answer": answer, "citations": citations}),
        usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15),
        stop_reason="end_turn",
    )


def _service(
    chunks: object,
    response: ChatResponse,
    *,
    policy: RAGPolicy | None = None,
) -> tuple[RAGService, FakeLLMProvider]:
    provider = FakeLLMProvider([response])
    service = RAGService(
        retrieval_service=cast(RetrievalService, StubRetrieval(chunks)),
        llm_provider=provider,
        policy=_policy() if policy is None else policy,
    )
    return service, provider


def test_valid_generated_citation_is_rebuilt_from_trusted_evidence() -> None:
    chunk = _chunk()
    service, provider = _service((chunk,), _response([_citation(chunk)]))

    result = asyncio.run(service.answer(_auth(), Query(text="What is governed?")))

    assert isinstance(result, CitedAnswerResult)
    assert result.answer.text == "Governed answer."
    assert result.answer.citations[0].model_dump() == {
        **_citation(chunk),
        "label": None,
    }
    assert result.usage is not None and result.usage.total_tokens == 15
    assert provider.requests[0].max_output_tokens == 512


def test_single_json_markdown_fence_is_accepted_before_strict_validation() -> None:
    chunk = _chunk()
    response = _response([_citation(chunk)])
    fenced = response.model_copy(update={"text": f"```json\n{response.text}\n```"})
    service, _provider = _service((chunk,), fenced)

    result = asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))

    assert isinstance(result, CitedAnswerResult)
    assert result.answer.text == "Governed answer."
    assert result.answer.citations[0].model_dump() == {
        **_citation(chunk),
        "label": None,
    }


def test_w10_prompt_uses_extractive_instruction_and_trusted_evidence_reference() -> None:
    chunk = _chunk(text="The approved answer is copied exactly from this evidence.")
    response = _response(
        [{"evidence_ref": "E1"}],
        answer="The approved answer is copied exactly from this evidence.",
    )
    service, provider = _service((chunk,), response, policy=_w10_policy())

    result = asyncio.run(service.answer(_auth(), Query(text="What is approved?")))

    assert isinstance(result, CitedAnswerResult)
    assert result.prompt_version == "w10-003.extractive.v2"
    assert result.answer.citations[0].model_dump() == {**_citation(chunk), "label": None}
    system_prompt = provider.requests[0].messages[0].content
    evidence = provider.requests[0].messages[1].content
    assert "character-for-character" in system_prompt
    assert '"evidence_ref":"E1"' in evidence
    assert chunk.document_version not in evidence
    assert chunk.chunk_id not in evidence


def test_w10_v2_prompt_requires_complete_multi_fact_multi_block_answer() -> None:
    first = _chunk(
        chunk_index=0,
        text="Golden-set Recall@5 must be at least 0.85.",
    )
    second_text = "At least 95% of eligible outcomes must be citation-valid "
    second_text += "answers or safe abstentions."
    second = _chunk(
        chunk_index=1,
        text=second_text,
    )
    answer = f"{first.text} {second.text}"
    service, provider = _service(
        (first, second),
        _response(
            [{"evidence_ref": "E1"}, {"evidence_ref": "E2"}],
            answer=answer,
        ),
        policy=_w10_policy(),
    )

    result = asyncio.run(
        service.answer(
            _auth(),
            Query(text="What are both initial quality targets?"),
        )
    )

    assert isinstance(result, CitedAnswerResult)
    assert result.answer.text == answer
    assert len(result.answer.citations) == 2
    system_prompt = provider.requests[0].messages[0].content
    assert "every distinct sentence or passage" in system_prompt
    assert "all of those facts" in system_prompt
    assert "one reference for every evidence block" in system_prompt


@pytest.mark.parametrize(
    "citations",
    [
        [{"evidence_ref": "E2"}],
        [{"evidence_ref": "E1"}, {"evidence_ref": "E1"}],
        [{"evidence_ref": "E1", "document_version": "fabricated"}],
    ],
)
def test_w10_unknown_duplicate_or_ambiguous_reference_safely_abstains(
    citations: list[dict[str, str]],
) -> None:
    service, _provider = _service(
        (_chunk(),),
        _response(citations, answer="raw-generated-answer-must-not-escape"),
        policy=_w10_policy(),
    )

    result = asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))

    assert result == AbstentionResult(
        reason="invalid_generated_citation",
        prompt_version="w10-003.extractive.v2",
        usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15),
    )


def test_explicit_provider_abstention_is_mapped_to_safe_result() -> None:
    chunk = _chunk()
    response = ChatResponse(
        text=json.dumps({"abstain": True}),
        usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15),
        stop_reason="end_turn",
    )
    service, _provider = _service((chunk,), response)

    result = asyncio.run(service.answer(_auth(), Query(text="Unknown fact")))

    assert result == AbstentionResult(
        reason="insufficient_evidence",
        prompt_version="w3-001.v1",
        usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"abstain": False},
        {"abstain": "true"},
        {"abstain": True, "reason": "model-controlled"},
    ],
)
def test_malformed_provider_abstention_fails_closed(payload: dict[str, object]) -> None:
    service, _provider = _service(
        (_chunk(),),
        ChatResponse(text=json.dumps(payload), stop_reason="end_turn"),
    )

    with pytest.raises(RAGOutputValidationError):
        asyncio.run(service.answer(_auth(), Query(text="Unknown fact")))


@pytest.mark.parametrize(
    "envelope",
    [
        "```\n{payload}\n```",
        "```JSON\n{payload}\n```",
        "prefix\n```json\n{payload}\n```",
        "```json\n{payload}\n```\nsuffix",
        "```json\n```json\n{payload}\n```\n```",
        "```json\n\n```",
    ],
)
def test_ambiguous_or_non_json_markdown_fences_fail_closed(envelope: str) -> None:
    chunk = _chunk()
    payload = _response([_citation(chunk)]).text
    service, _provider = _service(
        (chunk,),
        ChatResponse(text=envelope.format(payload=payload)),
    )

    with pytest.raises(RAGOutputValidationError):
        asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))


def test_valid_raw_string_uses_the_existing_policy_query_and_result_contract() -> None:
    chunk = _chunk()
    retrieval = StubRetrieval((chunk,))
    provider = FakeLLMProvider([_response([_citation(chunk)])])
    service = RAGService(
        retrieval_service=cast(RetrievalService, retrieval),
        llm_provider=provider,
        policy=_policy(),
    )

    result = asyncio.run(service.answer(_auth(), "  governed question  "))

    assert isinstance(result, CitedAnswerResult)
    assert retrieval.calls == 1
    assert provider.requests[0].messages[1].content.find("governed question") >= 0


@pytest.mark.parametrize(
    ("query", "content_type"),
    [
        ("", "text/plain"),
        (" \t\n ", "text/plain"),
        ("x" * 10_001, "text/plain"),
        ("valid", "application/json"),
        (object(), "text/plain"),
    ],
)
def test_invalid_input_stops_before_authorization_retrieval_and_provider(
    query: object,
    content_type: str,
) -> None:
    expired_auth = AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
        expires_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    retrieval = StubRetrieval((_chunk(),))
    provider = FakeLLMProvider()
    service = RAGService(
        retrieval_service=cast(RetrievalService, retrieval),
        llm_provider=provider,
        policy=_policy(),
    )

    with pytest.raises(GuardrailInputError) as raised:
        asyncio.run(
            service.answer(  # type: ignore[arg-type]
                expired_auth,
                query,
                content_type=content_type,
            )
        )

    assert raised.value.code == "guardrail_input_invalid"
    assert retrieval.calls == 0
    assert provider.requests == []


def _invalid_citations(chunk: RetrievedChunk) -> list[object]:
    valid = _citation(chunk)
    cases: list[object] = []
    for omitted in ("source_id", "document_id", "document_version", "chunk_id"):
        cases.append({key: value for key, value in valid.items() if key != omitted})
    cases.extend(
        [
            {**valid, "unknown": "field"},
            {**valid, "chunk_id": "malformed"},
            {**valid, "source_id": "fabricated-source"},
            {**valid, "document_id": "unauthorized-document"},
            {**valid, "document_version": "v2"},
            {**valid, "source_id": f"{chunk.source_id} "},
        ]
    )
    return cases


@pytest.mark.parametrize("case_index", range(10))
def test_every_invalid_generated_citation_case_safely_abstains(
    case_index: int,
) -> None:
    chunk = _chunk()
    invalid = _invalid_citations(chunk)[case_index]
    service, _provider = _service(
        (chunk,),
        _response([invalid], answer="raw-generated-answer-must-not-escape"),
    )

    result = asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))

    assert result == AbstentionResult(
        reason="invalid_generated_citation",
        prompt_version="w3-001.v1",
        usage=Usage(input_tokens=10, output_tokens=5, total_tokens=15),
    )
    serialized = json.dumps(result.model_dump(mode="json"))
    assert "raw-generated-answer-must-not-escape" not in serialized
    assert "citations" not in serialized


def test_invalid_provider_usage_raises_malformed_response() -> None:
    chunk = _chunk()
    invalid_usage = Usage.model_construct(
        input_tokens=2,
        output_tokens=3,
        total_tokens=99,
        estimated_cost_usd=None,
    )
    response = ChatResponse.model_construct(
        text=json.dumps({"answer": "raw answer", "citations": [_citation(chunk)]}),
        tool_calls=(),
        usage=invalid_usage,
        stop_reason="end_turn",
    )
    service, _provider = _service((chunk,), response)

    with pytest.raises(LLMMalformedResponseError):
        asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))


@pytest.mark.parametrize(
    "raw_text",
    [
        '{"answer":"raw answer"}',
        '{"answer":"raw answer","citations":[{"source_id":"first",'
        '"source_id":"second","document_id":"policy-001",'
        '"document_version":"v1","chunk_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}',
    ],
)
def test_missing_or_duplicate_citation_content_safely_abstains(
    raw_text: str,
) -> None:
    service, _provider = _service(
        (_chunk(),),
        ChatResponse(
            text=raw_text,
            usage=Usage(input_tokens=4, output_tokens=2, total_tokens=6),
        ),
    )

    result = asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))

    assert isinstance(result, AbstentionResult)
    assert result.reason == "invalid_generated_citation"
    assert result.usage is not None and result.usage.total_tokens == 6


@pytest.mark.parametrize(
    "provider_error",
    [
        LLMAuthenticationError(),
        LLMAuthorizationError(),
        LLMTimeoutError(),
        LLMThrottlingError(),
        LLMUnavailableError(),
    ],
)
def test_operational_provider_failures_never_become_abstentions(
    provider_error: LLMError,
) -> None:
    provider = FakeLLMProvider([provider_error])
    service = RAGService(
        retrieval_service=cast(RetrievalService, StubRetrieval((_chunk(),))),
        llm_provider=provider,
        policy=_policy(),
    )

    with pytest.raises(type(provider_error)):
        asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))


@pytest.mark.parametrize(
    ("chunks", "reason"),
    [
        ((), "insufficient_evidence"),
        ((_chunk(score=0.49),), "insufficient_evidence"),
        ((_chunk(tenant_id="tenant-b"),), "no_authorized_evidence"),
        (
            (
                _chunk(document_version="v1", chunk_index=1),
                _chunk(document_version="v2", chunk_index=2),
            ),
            "conflicting_evidence",
        ),
        ((object(),), "malformed_evidence"),
        ((_chunk(text="x" * 12000),), "insufficient_evidence"),
    ],
)
def test_pre_provider_abstentions_never_invoke_provider(
    chunks: object,
    reason: str,
) -> None:
    provider = FakeLLMProvider()
    service = RAGService(
        retrieval_service=cast(RetrievalService, StubRetrieval(chunks)),
        llm_provider=provider,
        policy=_policy(),
    )

    result = asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))

    assert isinstance(result, AbstentionResult)
    assert result.reason == reason
    assert result.usage is None
    assert provider.requests == []


def test_retrieval_authorization_denial_is_preserved() -> None:
    service = RAGService(
        retrieval_service=cast(RetrievalService, FailingRetrieval()),
        llm_provider=FakeLLMProvider(),
        policy=_policy(),
    )

    with pytest.raises(VectorStoreAuthorizationError):
        asyncio.run(service.answer(_auth(), Query(text="Synthetic query")))


def test_inactive_authorization_stops_before_retrieval_and_generation() -> None:
    expired_auth = AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
        expires_at=datetime(2000, 1, 1, tzinfo=UTC),
    )
    retrieval = StubRetrieval((_chunk(),))
    provider = FakeLLMProvider()
    service = RAGService(
        retrieval_service=cast(RetrievalService, retrieval),
        llm_provider=provider,
        policy=_policy(),
    )

    with pytest.raises(VectorStoreAuthorizationError):
        asyncio.run(service.answer(expired_auth, Query(text="Synthetic query")))

    assert retrieval.calls == 0
    assert provider.requests == []


def test_unparseable_json_and_unexpected_tool_call_fail_closed() -> None:
    chunk = _chunk()
    malformed_service, _provider = _service((chunk,), ChatResponse(text="not-json", usage=None))
    tool_service, _provider = _service(
        (chunk,),
        ChatResponse(tool_calls=(ToolCall(tool_call_id="call-1", name="lookup", arguments={}),)),
    )

    with pytest.raises(RAGOutputValidationError):
        asyncio.run(malformed_service.answer(_auth(), Query(text="Synthetic query")))
    with pytest.raises(RAGOutputValidationError):
        asyncio.run(tool_service.answer(_auth(), Query(text="Synthetic query")))
