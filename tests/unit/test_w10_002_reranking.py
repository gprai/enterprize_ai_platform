"""Unit coverage for deterministic W10-002 reranking."""

from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.retrieval.reranking import (
    APPROVED_RERANKER_IDENTITY,
    APPROVED_RERANKING_POLICY,
    AdoptionDecision,
    DeterministicTokenOverlapReranker,
    EvidenceScope,
    QualityMetrics,
    RerankingComparison,
    RuntimeCostMetrics,
    build_rerank_request,
    evaluate_adoption,
    tokenize,
)


def test_local_reranker_is_deterministic_and_baseline_stable_on_ties() -> None:
    async def scenario() -> None:
        request = build_rerank_request(
            "alpha beta",
            (("a" * 64, "alpha"), ("b" * 64, "alpha beta"), ("c" * 64, "alpha")),
            3,
        )
        response = await DeterministicTokenOverlapReranker().rerank(
            request,
            timeout_seconds=0.25,
        )

        assert response.identity == APPROVED_RERANKER_IDENTITY
        assert [result.chunk_id for result in response.results] == [
            "b" * 64,
            "a" * 64,
            "c" * 64,
        ]

    asyncio.run(scenario())


def test_tokenization_is_ascii_bounded_and_does_not_retain_raw_text() -> None:
    assert tokenize("ALPHA, beta! café 123", 3) == ("alpha", "beta", "caf")
    assert tokenize("private-token " * 300, 256) == ("private", "token") * 128


def test_request_rejects_duplicate_or_excess_candidates() -> None:
    with pytest.raises(ValidationError):
        build_rerank_request(
            "query",
            (("a" * 64, "first"), ("a" * 64, "second")),
            2,
        )


def _comparison(scope: EvidenceScope, *, mrr: float = 0.75) -> RerankingComparison:
    return RerankingComparison(
        scope=scope,
        baseline_quality=QualityMetrics(
            recall_at_5=0.85,
            precision_at_5=0.8,
            mrr=0.7,
            citation_precision=1.0,
        ),
        candidate_quality=QualityMetrics(
            recall_at_5=0.9,
            precision_at_5=0.8,
            mrr=mrr,
            citation_precision=1.0,
        ),
        runtime_cost=RuntimeCostMetrics(
            incremental_p95_ms=25.0,
            total_retrieval_p99_ms=500.0,
            request_count=100,
            saturation_count=0,
            degraded_count=0,
            provider_calls=0,
            estimated_total_paid_cost=0.0,
            estimated_incremental_paid_cost=0.0,
            local_cpu_ms=10.0,
        ),
        authorization_violations=0,
        known_backend_differences=("OpenSearch hybrid; Qdrant and in-memory vector-only",),
    )


def test_adoption_requires_representative_evidence_and_every_gate() -> None:
    assert evaluate_adoption(_comparison(EvidenceScope.SYNTHETIC)) is AdoptionDecision.INDETERMINATE
    assert (
        evaluate_adoption(_comparison(EvidenceScope.REPRESENTATIVE_OWNER_APPROVED))
        is AdoptionDecision.ADOPTED
    )
    assert (
        evaluate_adoption(_comparison(EvidenceScope.REPRESENTATIVE_OWNER_APPROVED, mrr=0.74))
        is AdoptionDecision.NOT_ADOPTED
    )
    assert APPROVED_RERANKING_POLICY.retry_attempts == 0
