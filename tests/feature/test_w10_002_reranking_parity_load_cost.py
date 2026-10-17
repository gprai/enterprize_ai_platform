"""Feature coverage for parity, no-queue load behavior, and local cost gates."""

from __future__ import annotations

import asyncio

from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.retrieval.models import CollectionSpec, Query
from enterprise_ai_platform.retrieval.reranking import (
    AdoptionDecision,
    EvidenceScope,
    QualityMetrics,
    RerankingComparison,
    RuntimeCostMetrics,
    evaluate_adoption,
)
from enterprise_ai_platform.retrieval.service import RetrievalService
from tests.fakes.w10_002_reranking import (
    RecordingReranker,
    StaticVectorStore,
    reader_auth,
    retrieved_chunks,
)


def test_fifth_concurrent_call_degrades_without_queue_or_extra_provider_call() -> None:
    async def scenario() -> None:
        baseline = retrieved_chunks("first", "second")
        reranker = RecordingReranker(blocked=True)
        service = RetrievalService(
            embedder=FakeEmbeddingProvider(),
            vector_store=StaticVectorStore(baseline),
            collection_spec=CollectionSpec(name="w10_002_load"),
            reranker=reranker,
        )
        query = Query(text="load", top_k=2)
        first_four = [asyncio.create_task(service.retrieve(query, reader_auth())) for _ in range(4)]
        while len(reranker.calls) < 4:
            await asyncio.sleep(0)

        fifth = await service.retrieve(query, reader_auth())
        assert fifth == baseline
        assert len(reranker.calls) == 4

        reranker.release.set()
        await asyncio.gather(*first_four)

    asyncio.run(scenario())


def test_representative_zero_paid_call_evidence_can_pass_adoption_gate() -> None:
    comparison = RerankingComparison(
        scope=EvidenceScope.REPRESENTATIVE_OWNER_APPROVED,
        baseline_quality=QualityMetrics(
            recall_at_5=0.85,
            precision_at_5=0.8,
            mrr=0.7,
            citation_precision=1.0,
        ),
        candidate_quality=QualityMetrics(
            recall_at_5=0.9,
            precision_at_5=0.81,
            mrr=0.76,
            citation_precision=1.0,
        ),
        runtime_cost=RuntimeCostMetrics(
            incremental_p95_ms=50.0,
            total_retrieval_p99_ms=700.0,
            request_count=100,
            saturation_count=0,
            degraded_count=0,
            provider_calls=0,
            estimated_total_paid_cost=0.0,
            estimated_incremental_paid_cost=0.0,
            local_cpu_ms=20.0,
        ),
        authorization_violations=0,
        known_backend_differences=("OpenSearch hybrid; Qdrant and in-memory vector-only",),
    )

    assert evaluate_adoption(comparison) is AdoptionDecision.ADOPTED
