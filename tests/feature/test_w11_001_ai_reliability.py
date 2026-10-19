"""W11-001 acceptance checks for fail-closed release and rollback governance."""

from __future__ import annotations

from decimal import Decimal

from enterprise_ai_platform.telemetry.ai_reliability import (
    BurnRateEvidence,
    CollectionStatus,
    DecisionStatus,
    EvaluationBatch,
    ReleaseAction,
    evaluate_batch,
    load_ai_reliability_policy,
)
from tests.fakes.w11_001_ai_reliability import OBSERVED_AT, passing_batch


def test_objective_failure_freezes_release_and_requires_review() -> None:
    policy = load_ai_reliability_policy()
    batch = passing_batch(policy)
    evidence = list(batch.sli_evidence)
    citation_index = next(
        index for index, item in enumerate(evidence) if item.sli_id == "citation_coverage"
    )
    evidence[citation_index] = evidence[citation_index].model_copy(
        update={"observed_value": Decimal("0.99")}
    )
    _, _, decision = evaluate_batch(
        policy,
        EvaluationBatch(sli_evidence=tuple(evidence), burn_evidence=batch.burn_evidence),
    )
    assert decision.status is DecisionStatus.FAIL
    assert decision.action is ReleaseAction.RELEASE_FROZEN_ROLLBACK_REVIEW
    assert decision.release_allowed is False
    assert decision.rollback_review_required is True
    assert decision.automatic_rollback is False


def test_not_run_blocks_release_without_claiming_failure() -> None:
    policy = load_ai_reliability_policy()
    batch = passing_batch(policy)
    evidence = list(batch.sli_evidence)
    evidence[0] = evidence[0].model_copy(
        update={
            "collection_status": CollectionStatus.NOT_RUN,
            "sample_count": 0,
            "observed_value": None,
            "source_identity_sha256": None,
            "correlated_request_count": 0,
            "correlation_digest_sha256": None,
            "reason": "owner execution pending",
        }
    )
    _, _, decision = evaluate_batch(
        policy,
        EvaluationBatch(sli_evidence=tuple(evidence), burn_evidence=batch.burn_evidence),
    )
    assert decision.status is DecisionStatus.NOT_RUN
    assert decision.action is ReleaseAction.RELEASE_BLOCKED
    assert decision.rollback_review_required is False


def test_paired_fast_burn_freezes_release_even_when_sli_window_passes() -> None:
    policy = load_ai_reliability_policy()
    batch = passing_batch(policy)
    burning = BurnRateEvidence(
        tier="fast",
        collection_status=CollectionStatus.MEASURED,
        short_window_burn_factor=Decimal("14.4"),
        long_window_burn_factor=Decimal("14.4"),
        short_window_events=20,
        observed_at=OBSERVED_AT,
    )
    _, burn, decision = evaluate_batch(
        policy,
        EvaluationBatch(sli_evidence=batch.sli_evidence, burn_evidence=(burning,)),
    )
    assert burn[0].status is DecisionStatus.FAIL
    assert decision.status is DecisionStatus.FAIL
    assert decision.action is ReleaseAction.RELEASE_FROZEN_ROLLBACK_REVIEW
