"""Sequential provider-neutral evaluation through the approved W3-001 RAG service."""

from __future__ import annotations

from collections.abc import Callable
from typing import Protocol, cast, runtime_checkable

from enterprise_ai_platform.llm.errors import LLMMalformedResponseError
from enterprise_ai_platform.llm.models import Usage
from enterprise_ai_platform.rag.config import RAGPolicy
from enterprise_ai_platform.rag.errors import RAGOutputValidationError
from enterprise_ai_platform.rag.models import AbstentionResult, CitedAnswerResult
from enterprise_ai_platform.rag.service import RAGService
from enterprise_ai_platform.retrieval.authorization import is_retrieval_authorized
from enterprise_ai_platform.retrieval.models import RetrievedChunk
from enterprise_ai_platform.retrieval.service import RetrievalService

from .fixtures import CaseFixture, fixture_for, provider_protocol
from .models import (
    ActualOutcome,
    CaseExecution,
    ExpectedAbstentionReason,
    ExpectedErrorCode,
    GoldenCase,
    GoldenDataset,
    Provenance,
)

CaseFixtureFactory = Callable[[GoldenCase], CaseFixture]


@runtime_checkable
class Evaluator(Protocol):
    """Provider-neutral deterministic evaluation boundary."""

    async def evaluate(
        self,
        dataset: GoldenDataset,
        policy: RAGPolicy,
    ) -> tuple[CaseExecution, ...]: ...


class DeterministicRAGEvaluator:
    """Evaluate Q1-Q39 sequentially with no external clients or parallel scheduling."""

    def __init__(self, *, fixture_factory: CaseFixtureFactory = fixture_for) -> None:
        self._fixture_factory = fixture_factory

    async def evaluate(
        self,
        dataset: GoldenDataset,
        policy: RAGPolicy,
    ) -> tuple[CaseExecution, ...]:
        results: list[CaseExecution] = []
        for case in dataset.cases:
            results.append(await self._evaluate_case(case, policy))
        return tuple(results)

    async def _evaluate_case(self, case: GoldenCase, policy: RAGPolicy) -> CaseExecution:
        fixture = self._fixture_factory(case)
        service = RAGService(
            retrieval_service=cast(RetrievalService, fixture.retrieval),
            llm_provider=provider_protocol(fixture),
            policy=policy,
        )
        outcome: ActualOutcome = "ERROR"
        answer_text: str | None = None
        abstention_reason: ExpectedAbstentionReason | None = None
        error_code: ExpectedErrorCode | None = None
        citations: tuple[Provenance, ...] = ()
        usage: Usage | None = None
        try:
            result = await service.answer(fixture.auth_context, fixture.query)
            usage = result.usage
            if isinstance(result, CitedAnswerResult):
                outcome = "ANSWERED"
                answer_text = result.answer.text
                citations = tuple(
                    Provenance(
                        source_id=item.source_id,
                        document_id=item.document_id,
                        document_version=item.document_version,
                        chunk_id=item.chunk_id,
                    )
                    for item in result.answer.citations
                )
            elif isinstance(result, AbstentionResult):
                outcome = "ABSTAINED"
                abstention_reason = result.reason
        except RAGOutputValidationError:
            error_code = "rag_output_validation_error"
        except LLMMalformedResponseError:
            error_code = "llm_malformed_response_error"

        raw = fixture.retrieval.raw_result
        valid_raw = (
            tuple(item for item in raw if isinstance(item, RetrievedChunk))
            if isinstance(raw, tuple)
            else ()
        )
        authorized = tuple(
            sorted(
                (
                    item
                    for item in valid_raw
                    if is_retrieval_authorized(item, fixture.auth_context)
                    and item.score >= policy.min_score
                ),
                key=lambda item: (-item.score, item.chunk_id),
            )
        )
        provider_calls = len(fixture.provider.requests)
        violations: list[str] = []
        if case.expected_provider_calls == 0 and provider_calls:
            violations.append("pre_provider_abstention_invoked_provider")
        if case.acl_expectation.startswith("DENIED_") and provider_calls:
            violations.append("denied_evidence_reached_provider")
        if case.expected_outcome != "ANSWERED" and (answer_text is not None or citations):
            violations.append("suppressed_content_exposed")
        exposed_invalid = int(
            outcome == "ANSWERED"
            and any(
                item.chunk_id not in case.expected_chunk_ids for item in citations
            )
        )
        return CaseExecution(
            case_id=case.case_id,
            expected_outcome=case.expected_outcome,
            release_blocking=case.release_blocking,
            actual_outcome=outcome,
            answer_text=answer_text,
            abstention_reason=abstention_reason,
            error_code=error_code,
            retrieved_source_ids=tuple(item.source_id for item in authorized[:5]),
            citations=citations,
            provider_calls=provider_calls,
            usage=usage,
            security_violations=tuple(violations),
            exposed_invalid_citations=exposed_invalid,
        )
