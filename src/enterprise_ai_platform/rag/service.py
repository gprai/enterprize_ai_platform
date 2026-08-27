"""Authorization-first cited-RAG orchestration with fail-closed citations."""

from __future__ import annotations

from typing import cast

from pydantic import ValidationError

from enterprise_ai_platform.guardrails.policy import validate_rag_input
from enterprise_ai_platform.json_contracts import (
    DuplicateJSONKeyError,
    JSONValue,
    strict_json_loads,
)
from enterprise_ai_platform.llm.errors import LLMMalformedResponseError
from enterprise_ai_platform.llm.models import ChatResponse, Usage
from enterprise_ai_platform.llm.provider import LLMProvider
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.errors import RAGOutputValidationError
from enterprise_ai_platform.rag.models import (
    AbstentionReason,
    AbstentionResult,
    CitedAnswerResult,
    RAGResult,
)
from enterprise_ai_platform.rag.prompt import (
    EvidenceBlock,
    build_rag_request,
    select_complete_evidence_blocks,
)
from enterprise_ai_platform.retrieval.authorization import (
    is_retrieval_authorized,
    require_active_context,
)
from enterprise_ai_platform.retrieval.models import (
    Answer,
    AuthContext,
    Citation,
    Query,
    RetrievedChunk,
)
from enterprise_ai_platform.retrieval.service import RetrievalService

_REQUIRED_CITATION_KEYS = frozenset(
    {"source_id", "document_id", "document_version", "chunk_id"}
)
_ALLOWED_CITATION_KEYS = _REQUIRED_CITATION_KEYS | {"label"}


def _abstain(
    reason: AbstentionReason,
    policy: RAGPolicy,
    usage: Usage | None = None,
) -> AbstentionResult:
    return AbstentionResult(reason=reason, prompt_version=policy.prompt_version, usage=usage)


def _validated_chunks(raw_chunks: object) -> tuple[RetrievedChunk, ...] | None:
    if not isinstance(raw_chunks, tuple):
        return None
    checked: list[RetrievedChunk] = []
    for raw_chunk in raw_chunks:
        if not isinstance(raw_chunk, RetrievedChunk):
            return None
        try:
            checked.append(
                RetrievedChunk.model_validate(raw_chunk.model_dump(mode="python"), strict=True)
            )
        except ValidationError:
            return None
    return tuple(checked)


def _has_conflicting_versions(chunks: tuple[RetrievedChunk, ...]) -> bool:
    versions: dict[tuple[str, str], set[str]] = {}
    for chunk in chunks:
        versions.setdefault((chunk.source_id, chunk.document_id), set()).add(
            chunk.document_version
        )
    return any(len(document_versions) > 1 for document_versions in versions.values())


def _validated_provider_response(raw_response: object) -> ChatResponse:
    if not isinstance(raw_response, ChatResponse):
        raise LLMMalformedResponseError
    try:
        return ChatResponse.model_validate(raw_response.model_dump(mode="python"), strict=True)
    except ValidationError:
        raise LLMMalformedResponseError from None


def _generated_citation_key(raw: JSONValue) -> tuple[str, str, str, str] | None:
    if not isinstance(raw, dict) or set(raw) - _ALLOWED_CITATION_KEYS:
        return None
    if not _REQUIRED_CITATION_KEYS.issubset(raw):
        return None
    label = raw.get("label")
    if label is not None and not isinstance(label, str):
        return None
    values = tuple(raw[key] for key in ("source_id", "document_id", "document_version", "chunk_id"))
    if not all(isinstance(value, str) for value in values):
        return None
    source_id, document_id, document_version, chunk_id = cast(tuple[str, str, str, str], values)
    try:
        candidate = Citation(
            source_id=source_id,
            document_id=document_id,
            document_version=document_version,
            chunk_id=chunk_id,
            label=label,
        )
    except ValidationError:
        return None
    if (
        candidate.source_id != source_id
        or candidate.document_id != document_id
        or candidate.document_version != document_version
        or candidate.chunk_id != chunk_id
    ):
        return None
    return (source_id, document_id, document_version, chunk_id)


def _parse_generated_answer(
    response: ChatResponse,
    evidence_blocks: tuple[EvidenceBlock, ...],
    policy: RAGPolicy,
) -> RAGResult:
    if response.tool_calls:
        raise RAGOutputValidationError
    try:
        generated = strict_json_loads(response.text)
    except DuplicateJSONKeyError:
        return _abstain("invalid_generated_citation", policy, response.usage)
    except (TypeError, ValueError):
        raise RAGOutputValidationError from None
    if not isinstance(generated, dict):
        raise RAGOutputValidationError
    if set(generated) - {"answer", "citations"} or "answer" not in generated:
        raise RAGOutputValidationError
    if "citations" not in generated:
        return _abstain("invalid_generated_citation", policy, response.usage)
    raw_citations = generated["citations"]
    if not isinstance(raw_citations, list) or not raw_citations:
        return _abstain("invalid_generated_citation", policy, response.usage)

    supplied_counts: dict[tuple[str, str, str, str], int] = {}
    for block in evidence_blocks:
        supplied_counts[block.provenance] = supplied_counts.get(block.provenance, 0) + 1
    requested: set[tuple[str, str, str, str]] = set()
    for raw_citation in raw_citations:
        citation_key = _generated_citation_key(raw_citation)
        if citation_key is None or supplied_counts.get(citation_key) != 1:
            return _abstain("invalid_generated_citation", policy, response.usage)
        requested.add(citation_key)

    answer_text = generated["answer"]
    if not isinstance(answer_text, str) or not answer_text.strip():
        raise RAGOutputValidationError

    trusted_citations = tuple(
        Citation(
            source_id=block.chunk.source_id,
            document_id=block.chunk.document_id,
            document_version=block.chunk.document_version,
            chunk_id=block.chunk.chunk_id,
            label=None,
        )
        for block in evidence_blocks
        if block.provenance in requested
    )
    if not trusted_citations:
        return _abstain("invalid_generated_citation", policy, response.usage)
    answer = Answer(text=answer_text, citations=trusted_citations)
    return CitedAnswerResult(
        answer=answer,
        prompt_version=policy.prompt_version,
        usage=response.usage,
    )


class RAGService:
    """Compose retrieval, evidence policy, generation, and citation validation."""

    def __init__(
        self,
        *,
        retrieval_service: RetrievalService,
        llm_provider: LLMProvider,
        policy: RAGPolicy,
    ) -> None:
        self._retrieval_service = retrieval_service
        self._llm_provider = llm_provider
        self._policy = policy

    async def answer(
        self,
        auth_context: AuthContext,
        query: Query | str,
        *,
        content_type: str = "text/plain",
    ) -> RAGResult:
        """Return a cited answer or a policy-classified safe abstention."""

        validated_query = validate_rag_input(query, content_type=content_type)
        require_active_context(auth_context)
        policy_query = Query(
            text=validated_query.text,
            top_k=self._policy.top_k,
            min_score=self._policy.min_score,
        )
        raw_chunks = await self._retrieval_service.retrieve(policy_query, auth_context)
        chunks = _validated_chunks(raw_chunks)
        if chunks is None:
            return _abstain("malformed_evidence", self._policy)
        if not chunks:
            return _abstain("insufficient_evidence", self._policy)

        authorized = tuple(
            chunk for chunk in chunks if is_retrieval_authorized(chunk, auth_context)
        )
        if not authorized:
            return _abstain("no_authorized_evidence", self._policy)
        qualifying = tuple(
            sorted(
                (chunk for chunk in authorized if chunk.score >= self._policy.min_score),
                key=lambda chunk: (-chunk.score, chunk.chunk_id),
            )
        )
        if len(qualifying) < self._policy.minimum_qualifying_chunks:
            return _abstain("insufficient_evidence", self._policy)
        if _has_conflicting_versions(qualifying):
            return _abstain("conflicting_evidence", self._policy)

        evidence_blocks = select_complete_evidence_blocks(
            qualifying,
            max_context_characters=self._policy.max_context_characters,
        )
        if len(evidence_blocks) < self._policy.minimum_qualifying_chunks:
            return _abstain("insufficient_evidence", self._policy)

        request = build_rag_request(policy_query, evidence_blocks, self._policy)
        response = _validated_provider_response(await self._llm_provider.chat(request))
        return _parse_generated_answer(response, evidence_blocks, self._policy)
