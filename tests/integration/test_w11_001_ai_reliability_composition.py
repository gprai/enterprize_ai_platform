"""Composition checks from evidence through the governed release decision."""

from enterprise_ai_platform.telemetry.ai_reliability import (
    DecisionStatus,
    EvaluationBatch,
    ReleaseAction,
    evaluate_batch,
    load_ai_reliability_policy,
)
from tests.fakes.w11_001_ai_reliability import passing_batch


def test_complete_healthy_evidence_allows_release_without_closing_gaps() -> None:
    policy = load_ai_reliability_policy()
    evaluations, burn, decision = evaluate_batch(policy, passing_batch(policy))
    assert len(evaluations) == 17
    assert len(burn) == 2
    assert {item.status for item in evaluations} == {DecisionStatus.PASS}
    assert {item.status for item in burn} == {DecisionStatus.PASS}
    assert decision.status is DecisionStatus.PASS
    assert decision.action is ReleaseAction.RELEASE_ALLOWED
    assert decision.release_allowed is True
    assert decision.gaps_remaining_open == ("GAP-07", "GAP-10", "GAP-14")


def test_omitted_sli_blocks_release_as_indeterminate() -> None:
    policy = load_ai_reliability_policy()
    complete = passing_batch(policy)
    incomplete = EvaluationBatch(
        sli_evidence=complete.sli_evidence[:-1],
        burn_evidence=complete.burn_evidence,
    )
    _, _, decision = evaluate_batch(policy, incomplete)
    assert decision.status is DecisionStatus.INDETERMINATE
    assert decision.action is ReleaseAction.RELEASE_BLOCKED
    assert decision.release_allowed is False
    assert "cost_per_successful_query_usd" in " ".join(decision.reasons)
