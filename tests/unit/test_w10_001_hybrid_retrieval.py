"""Unit tests for deterministic W10-001 hybrid policy and fusion."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.retrieval.errors import VectorStoreValidationError
from enterprise_ai_platform.retrieval.hybrid import (
    APPROVED_HYBRID_POLICY,
    APPROVED_HYBRID_POLICY_SHA256,
    HybridRetrievalPolicy,
    RankedCandidate,
    fuse_ranked_candidates,
    normalize_channel_scores,
)
from enterprise_ai_platform.retrieval.models import Chunk
from tests.fakes.w10_001_hybrid_retrieval import make_chunk


def test_policy_identity_and_candidate_budget_are_exact_and_stable() -> None:
    assert APPROVED_HYBRID_POLICY.schema_version == "w10-001.hybrid-retrieval.v1"
    assert APPROVED_HYBRID_POLICY.lexical_analyzer == "standard"
    assert APPROVED_HYBRID_POLICY.lexical_similarity == "BM25"
    assert APPROVED_HYBRID_POLICY.candidate_limit(1) == 20
    assert APPROVED_HYBRID_POLICY.candidate_limit(5) == 20
    assert APPROVED_HYBRID_POLICY.candidate_limit(25) == 100
    assert APPROVED_HYBRID_POLICY.candidate_limit(100) == 100
    assert APPROVED_HYBRID_POLICY.identity_sha256() == APPROVED_HYBRID_POLICY_SHA256
    assert len(APPROVED_HYBRID_POLICY_SHA256) == 64


def test_policy_is_strict_and_weights_must_sum_to_one() -> None:
    with pytest.raises(ValidationError):
        HybridRetrievalPolicy.model_validate(
            {**APPROVED_HYBRID_POLICY.model_dump(), "unexpected": True},
            strict=True,
        )
    with pytest.raises(ValidationError, match="sum to one"):
        HybridRetrievalPolicy(vector_weight=0.6, lexical_weight=0.5)


def test_channel_normalization_deduplicates_and_handles_equal_scores() -> None:
    first = make_chunk(0)
    second = make_chunk(1)
    candidates, scores = normalize_channel_scores(
        (
            RankedCandidate(first, 7.0),
            RankedCandidate(first, 6.0),
            RankedCandidate(second, 7.0),
        )
    )

    assert tuple(candidates) == (first.chunk_id, second.chunk_id)
    assert scores == {first.chunk_id: 1.0, second.chunk_id: 1.0}


def test_fusion_is_deterministic_and_uses_declared_tie_breaks() -> None:
    vector_only = make_chunk(0)
    both = make_chunk(1)
    lexical_only = make_chunk(2)

    results = fuse_ranked_candidates(
        vector_candidates=(
            RankedCandidate(vector_only, 10.0),
            RankedCandidate(both, 0.0),
        ),
        lexical_candidates=(
            RankedCandidate(both, 20.0),
            RankedCandidate(lexical_only, 0.0),
        ),
        top_k=3,
        min_score=-1.0,
    )

    assert [result.chunk_id for result in results] == [
        both.chunk_id,
        vector_only.chunk_id,
        lexical_only.chunk_id,
    ]
    assert [result.score for result in results] == [0.5, 0.5, 0.0]

    filtered = fuse_ranked_candidates(
        vector_candidates=(
            RankedCandidate(vector_only, 10.0),
            RankedCandidate(both, 0.0),
        ),
        lexical_candidates=(
            RankedCandidate(both, 20.0),
            RankedCandidate(lexical_only, 0.0),
        ),
        top_k=3,
        min_score=0.51,
    )
    assert filtered == ()


def test_conflicting_duplicate_identity_fails_closed() -> None:
    original = make_chunk(0)
    conflicting = Chunk(**{**original.model_dump(), "text": "Conflicting synthetic text"})

    with pytest.raises(VectorStoreValidationError):
        fuse_ranked_candidates(
            vector_candidates=(RankedCandidate(original, 1.0),),
            lexical_candidates=(RankedCandidate(conflicting, 1.0),),
            top_k=1,
            min_score=-1.0,
        )


def test_final_equal_score_tie_breaks_by_stable_chunk_identity() -> None:
    first = make_chunk(0)
    second = make_chunk(1)
    results = fuse_ranked_candidates(
        vector_candidates=(RankedCandidate(second, 1.0), RankedCandidate(first, 1.0)),
        lexical_candidates=(RankedCandidate(first, 1.0), RankedCandidate(second, 1.0)),
        top_k=2,
        min_score=-1.0,
    )

    assert [result.chunk_id for result in results] == sorted([first.chunk_id, second.chunk_id])


@pytest.mark.parametrize("score", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_provider_scores_fail_closed(score: float) -> None:
    with pytest.raises(VectorStoreValidationError):
        RankedCandidate(make_chunk(0), score)
