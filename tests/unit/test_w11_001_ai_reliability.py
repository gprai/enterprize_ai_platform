"""Unit checks for W11-001 objective and burn-rate decisions."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from enterprise_ai_platform.telemetry.ai_reliability import (
    BurnRateEvidence,
    CollectionStatus,
    DecisionStatus,
    SLIContract,
    SLIEvidence,
    evaluate_burn_rate,
    evaluate_sli,
    load_ai_reliability_policy,
)

OBSERVED_AT = datetime(2026, 10, 19, tzinfo=UTC)


def _contract(sli_id: str) -> SLIContract:
    policy = load_ai_reliability_policy()
    return next(item for item in policy.slis if item.sli_id == sli_id)


def test_insufficient_sample_never_becomes_a_healthy_zero() -> None:
    contract = _contract("availability")
    evidence = SLIEvidence(
        sli_id=contract.sli_id,
        collection_status=CollectionStatus.MEASURED,
        sample_count=contract.minimum_samples - 1,
        observed_value=Decimal("1"),
        observed_at=OBSERVED_AT,
        source_identity_sha256="a" * 64,
    )
    result = evaluate_sli(contract, evidence)
    assert result.status is DecisionStatus.INDETERMINATE
    assert result.error_budget_remaining_ratio is None


def test_not_run_is_preserved_exactly() -> None:
    contract = _contract("answer_correctness")
    result = evaluate_sli(
        contract,
        SLIEvidence(
            sli_id=contract.sli_id,
            collection_status=CollectionStatus.NOT_RUN,
            sample_count=0,
            observed_at=OBSERVED_AT,
            reason="owner has not run TEST-001",
        ),
    )
    assert result.status is DecisionStatus.NOT_RUN
    assert result.observed_value is None


def test_minimum_and_maximum_thresholds_are_directional() -> None:
    policy = load_ai_reliability_policy()
    examples = (
        ("grounded_answer_rate", Decimal("0.94")),
        ("cost_per_successful_query_usd", Decimal("0.011")),
    )
    for sli_id, value in examples:
        contract = next(item for item in policy.slis if item.sli_id == sli_id)
        result = evaluate_sli(
            contract,
            SLIEvidence(
                sli_id=sli_id,
                collection_status=CollectionStatus.MEASURED,
                sample_count=contract.minimum_samples,
                observed_value=value,
                observed_at=OBSERVED_AT,
                source_identity_sha256="a" * 64,
            ),
        )
        assert result.status is DecisionStatus.FAIL


def test_zero_tolerance_security_sli_has_no_false_budget() -> None:
    contract = _contract("pii_leakage_rate")
    result = evaluate_sli(
        contract,
        SLIEvidence(
            sli_id=contract.sli_id,
            collection_status=CollectionStatus.MEASURED,
            sample_count=1,
            observed_value=Decimal(0),
            observed_at=OBSERVED_AT,
            source_identity_sha256="a" * 64,
        ),
    )
    assert result.status is DecisionStatus.PASS
    assert result.error_budget_remaining_ratio == Decimal(1)


def test_burn_alert_requires_both_windows_and_minimum_population() -> None:
    policy = load_ai_reliability_policy()
    one_window_only = evaluate_burn_rate(
        policy,
        BurnRateEvidence(
            tier="fast",
            collection_status=CollectionStatus.MEASURED,
            short_window_burn_factor=Decimal("14.4"),
            long_window_burn_factor=Decimal("14.3"),
            short_window_events=20,
            observed_at=OBSERVED_AT,
        ),
    )
    too_few = evaluate_burn_rate(
        policy,
        BurnRateEvidence(
            tier="slow",
            collection_status=CollectionStatus.MEASURED,
            short_window_burn_factor=Decimal("6"),
            long_window_burn_factor=Decimal("6"),
            short_window_events=19,
            observed_at=OBSERVED_AT,
        ),
    )
    assert one_window_only.status is DecisionStatus.PASS
    assert too_few.status is DecisionStatus.INDETERMINATE
