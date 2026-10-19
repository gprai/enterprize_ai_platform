"""Authorization-first cited-RAG orchestration with fail-closed citations."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from decimal import Decimal
from typing import Literal, cast

from pydantic import ValidationError

from enterprise_ai_platform.guardrails.errors import GuardrailInputError
from enterprise_ai_platform.guardrails.policy import validate_rag_input
from enterprise_ai_platform.json_contracts import (
    DuplicateJSONKeyError,
    JSONValue,
    strict_json_loads,
    unwrap_single_json_fence,
)
from enterprise_ai_platform.llm.errors import (
    LLMError,
    LLMMalformedResponseError,
    LLMValidationError,
)
from enterprise_ai_platform.llm.models import ChatResponse, Usage
from enterprise_ai_platform.llm.provider import LLMProvider
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.errors import RAGError, RAGOutputValidationError
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
from enterprise_ai_platform.retrieval.errors import (
    VectorStoreAuthorizationError,
    VectorStoreError,
    VectorStoreTimeoutError,
)
from enterprise_ai_platform.retrieval.models import (
    Answer,
    AuthContext,
    Citation,
    Query,
    RetrievedChunk,
)
from enterprise_ai_platform.retrieval.service import RetrievalService
from enterprise_ai_platform.telemetry.ai_operations import (
    AIOperationsDecision,
    AIOperationsPolicy,
    CostGuardReason,
    DependencyKind,
    PricingSnapshot,
    preflight_provider_call,
    record_ai_request_cost,
    record_dependency_result,
    record_rag_result,
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
    TelemetryScope,
)

_REQUIRED_CITATION_KEYS = frozenset({"source_id", "document_id", "document_version", "chunk_id"})
_ALLOWED_CITATION_KEYS = _REQUIRED_CITATION_KEYS | {"label"}
_REQUIRED_EVIDENCE_REFERENCE_KEYS = frozenset({"evidence_ref"})


def _utcnow() -> datetime:
    return datetime.now(UTC)


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
        versions.setdefault((chunk.source_id, chunk.document_id), set()).add(chunk.document_version)
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


def _generated_evidence_reference(raw: JSONValue) -> str | None:
    if not isinstance(raw, dict) or set(raw) != _REQUIRED_EVIDENCE_REFERENCE_KEYS:
        return None
    reference = raw["evidence_ref"]
    if not isinstance(reference, str):
        return None
    return reference


def _parse_generated_answer(
    response: ChatResponse,
    evidence_blocks: tuple[EvidenceBlock, ...],
    policy: RAGPolicy,
) -> RAGResult:
    if response.tool_calls:
        raise RAGOutputValidationError
    try:
        generated = strict_json_loads(unwrap_single_json_fence(response.text))
    except DuplicateJSONKeyError:
        return _abstain("invalid_generated_citation", policy, response.usage)
    except (TypeError, ValueError):
        raise RAGOutputValidationError from None
    if not isinstance(generated, dict):
        raise RAGOutputValidationError
    if set(generated) == {"abstain"}:
        if generated["abstain"] is True:
            return _abstain("insufficient_evidence", policy, response.usage)
        raise RAGOutputValidationError
    if set(generated) - {"answer", "citations"} or "answer" not in generated:
        raise RAGOutputValidationError
    if "citations" not in generated:
        return _abstain("invalid_generated_citation", policy, response.usage)
    raw_citations = generated["citations"]
    if not isinstance(raw_citations, list) or not raw_citations:
        return _abstain("invalid_generated_citation", policy, response.usage)

    requested: set[tuple[str, str, str, str]] = set()
    if policy.prompt_version in {
        "w10-003.extractive.v1",
        "w10-003.extractive.v2",
    }:
        references = {block.reference: block.provenance for block in evidence_blocks}
        requested_references: set[str] = set()
        for raw_citation in raw_citations:
            reference = _generated_evidence_reference(raw_citation)
            if (
                reference is None
                or reference not in references
                or reference in requested_references
            ):
                return _abstain("invalid_generated_citation", policy, response.usage)
            requested_references.add(reference)
            requested.add(references[reference])
    else:
        supplied_counts: dict[tuple[str, str, str, str], int] = {}
        for block in evidence_blocks:
            supplied_counts[block.provenance] = supplied_counts.get(block.provenance, 0) + 1
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
        telemetry: TelemetryRuntime | None = None,
        ai_operations_enabled: bool = False,
        ai_operations_policy: AIOperationsPolicy | None = None,
        ai_operations_pricing: PricingSnapshot | None = None,
        ai_operations_provider: Literal["bedrock", "fake"] = "fake",
        utcnow: Callable[[], datetime] = _utcnow,
    ) -> None:
        self._retrieval_service = retrieval_service
        self._llm_provider = llm_provider
        self._policy = policy
        self._telemetry = telemetry or NullTelemetryRuntime()
        if ai_operations_enabled and ai_operations_policy is None:
            raise ValueError("enabled AI operations requires an explicit policy")
        self._ai_operations_enabled = ai_operations_enabled
        self._ai_operations_policy = ai_operations_policy
        self._ai_operations_pricing = ai_operations_pricing
        self._ai_operations_provider = ai_operations_provider
        self._utcnow = utcnow

    def _observed_result(
        self,
        scope: TelemetryScope,
        result: RAGResult,
        *,
        retrieval_quality: float = 0.0,
    ) -> RAGResult:
        if isinstance(result, AbstentionResult):
            scope.finish(
                TelemetryOutcome.ABSTAINED,
                terminal_reason=result.reason,
            )
            if self._ai_operations_enabled:
                record_rag_result(
                    self._telemetry,
                    retrieval_quality=retrieval_quality,
                    groundedness_proxy=0.0,
                    citation_coverage=0.0,
                    abstained=True,
                )
        else:
            scope.finish(TelemetryOutcome.SUCCESS)
            if self._ai_operations_enabled:
                record_rag_result(
                    self._telemetry,
                    retrieval_quality=retrieval_quality,
                    groundedness_proxy=1.0,
                    citation_coverage=1.0,
                    abstained=False,
                )
        return result

    def _provider_preflight(self, maximum_output_tokens: int) -> AIOperationsDecision:
        if self._ai_operations_policy is None:
            return AIOperationsDecision(
                allowed=True,
                reason=CostGuardReason.DISABLED,
                safe_degraded=False,
            )
        return preflight_provider_call(
            self._ai_operations_policy,
            enabled=self._ai_operations_enabled,
            provider=self._ai_operations_provider,
            pricing=self._ai_operations_pricing,
            observed_at=self._utcnow(),
            maximum_input_tokens=self._ai_operations_policy.cost.maximum_input_tokens,
            maximum_output_tokens=maximum_output_tokens,
        )

    async def answer(
        self,
        auth_context: AuthContext,
        query: Query | str,
        *,
        content_type: str = "text/plain",
    ) -> RAGResult:
        """Return a cited answer or a policy-classified safe abstention."""

        with self._telemetry.start_scope(
            TelemetryStage.RAG,
            TelemetryOperation.ANSWER,
            prompt_version=self._policy.prompt_version,
        ) as rag_scope:
            try:
                with self._telemetry.start_scope(
                    TelemetryStage.GUARDRAIL,
                    TelemetryOperation.VALIDATE,
                    prompt_version=self._policy.prompt_version,
                ) as guardrail_scope:
                    try:
                        validated_query = validate_rag_input(
                            query,
                            content_type=content_type,
                        )
                    except GuardrailInputError:
                        guardrail_scope.finish(
                            TelemetryOutcome.REJECTED,
                            safe_error_code="guardrail_input_invalid",
                        )
                        raise
                    guardrail_scope.finish(TelemetryOutcome.SUCCESS)

                with self._telemetry.start_scope(
                    TelemetryStage.AUTHORIZATION,
                    TelemetryOperation.AUTHORIZE,
                ) as authorization_scope:
                    try:
                        require_active_context(auth_context)
                    except VectorStoreAuthorizationError:
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
                    self._telemetry.emit_event(
                        TelemetryEventName.SECURITY_DECISION,
                        SafeTelemetryAttributes(
                            stage=TelemetryStage.AUTHORIZATION,
                            operation=TelemetryOperation.AUTHORIZE,
                            outcome=TelemetryOutcome.SUCCESS,
                        ),
                    )

                policy_query = Query(
                    text=validated_query.text,
                    top_k=self._policy.top_k,
                    min_score=self._policy.min_score,
                )
                raw_chunks = await self._retrieval_service.retrieve(
                    policy_query,
                    auth_context,
                )
                if self._ai_operations_enabled:
                    record_dependency_result(
                        self._telemetry,
                        dependency=DependencyKind.RETRIEVAL,
                        available=True,
                    )
                chunks = _validated_chunks(raw_chunks)
                if chunks is None:
                    return self._observed_result(
                        rag_scope,
                        _abstain("malformed_evidence", self._policy),
                    )
                if not chunks:
                    return self._observed_result(
                        rag_scope,
                        _abstain("insufficient_evidence", self._policy),
                    )

                authorized = tuple(
                    chunk for chunk in chunks if is_retrieval_authorized(chunk, auth_context)
                )
                if not authorized:
                    return self._observed_result(
                        rag_scope,
                        _abstain("no_authorized_evidence", self._policy),
                    )
                qualifying = tuple(
                    sorted(
                        (chunk for chunk in authorized if chunk.score >= self._policy.min_score),
                        key=lambda chunk: (-chunk.score, chunk.chunk_id),
                    )
                )
                if len(qualifying) < self._policy.minimum_qualifying_chunks:
                    return self._observed_result(
                        rag_scope,
                        _abstain("insufficient_evidence", self._policy),
                    )
                if _has_conflicting_versions(qualifying):
                    return self._observed_result(
                        rag_scope,
                        _abstain("conflicting_evidence", self._policy),
                    )

                evidence_blocks = select_complete_evidence_blocks(
                    qualifying,
                    max_context_characters=self._policy.max_context_characters,
                    prompt_version=self._policy.prompt_version,
                )
                if len(evidence_blocks) < self._policy.minimum_qualifying_chunks:
                    return self._observed_result(
                        rag_scope,
                        _abstain("insufficient_evidence", self._policy),
                    )

                request = build_rag_request(policy_query, evidence_blocks, self._policy)
                cost_decision = self._provider_preflight(request.max_output_tokens)
                if not cost_decision.allowed:
                    record_ai_request_cost(
                        self._telemetry,
                        provider=self._ai_operations_provider,
                        decision=cost_decision,
                    )
                    raise LLMValidationError
                with self._telemetry.start_scope(
                    TelemetryStage.LLM,
                    TelemetryOperation.CHAT,
                    prompt_version=self._policy.prompt_version,
                ) as llm_scope:
                    response = _validated_provider_response(await self._llm_provider.chat(request))
                    if self._ai_operations_enabled:
                        record_dependency_result(
                            self._telemetry,
                            dependency=DependencyKind.MODEL,
                            available=True,
                        )
                    llm_scope.finish(TelemetryOutcome.SUCCESS)
                    actual_cost: Decimal | None = None
                    if response.usage is not None:
                        self._telemetry.record_tokens(
                            stage=TelemetryStage.LLM,
                            operation=TelemetryOperation.CHAT,
                            input_tokens=response.usage.input_tokens,
                            output_tokens=response.usage.output_tokens,
                            total_tokens=response.usage.total_tokens,
                            prompt_version=self._policy.prompt_version,
                        )
                        if self._ai_operations_pricing is not None:
                            actual_cost = (
                                Decimal(response.usage.input_tokens)
                                * self._ai_operations_pricing.input_token_rate_usd_per_million
                                + Decimal(response.usage.output_tokens)
                                * self._ai_operations_pricing.output_token_rate_usd_per_million
                            ) / Decimal(1_000_000)
                    if self._ai_operations_enabled:
                        record_ai_request_cost(
                            self._telemetry,
                            provider=self._ai_operations_provider,
                            decision=cost_decision,
                            actual_cost_usd=actual_cost,
                        )
                return self._observed_result(
                    rag_scope,
                    _parse_generated_answer(response, evidence_blocks, self._policy),
                    retrieval_quality=min(1.0, len(qualifying) / self._policy.top_k),
                )
            except VectorStoreAuthorizationError:
                rag_scope.finish(
                    TelemetryOutcome.DENIED,
                    terminal_reason="authorization_denied",
                    safe_error_code="vector_store_authorization_denied",
                )
                raise
            except VectorStoreTimeoutError:
                if self._ai_operations_enabled:
                    record_dependency_result(
                        self._telemetry,
                        dependency=DependencyKind.RETRIEVAL,
                        available=False,
                        degraded=True,
                    )
                rag_scope.finish(
                    TelemetryOutcome.TIMEOUT,
                    safe_error_code="vector_store_timeout",
                )
                raise
            except GuardrailInputError:
                rag_scope.finish(
                    TelemetryOutcome.REJECTED,
                    safe_error_code="guardrail_input_invalid",
                )
                raise
            except VectorStoreError as error:
                if self._ai_operations_enabled:
                    record_dependency_result(
                        self._telemetry,
                        dependency=DependencyKind.RETRIEVAL,
                        available=False,
                        degraded=True,
                    )
                rag_scope.finish(
                    TelemetryOutcome.ERROR,
                    safe_error_code=str(error.code),
                )
                raise
            except LLMError as error:
                if self._ai_operations_enabled:
                    record_dependency_result(
                        self._telemetry,
                        dependency=DependencyKind.MODEL,
                        available=False,
                        degraded=True,
                    )
                rag_scope.finish(
                    TelemetryOutcome.ERROR,
                    safe_error_code=str(error.code),
                )
                raise
            except RAGError as error:
                rag_scope.finish(
                    TelemetryOutcome.ERROR,
                    safe_error_code=str(error.code),
                )
                raise
