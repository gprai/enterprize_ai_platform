"""Unit tests for deterministic W8-004 capacity evaluation."""

from datetime import timedelta
from decimal import Decimal

import pytest

from enterprise_ai_platform.capacity import (
    CapacityClassification,
    CapacityValidationError,
    canonical_json,
    evaluate_capacity,
    fingerprint,
    load_capacity_policy,
)
from tests.fakes.w8_004_capacity import valid_sample


def test_valid_bounded_sample_produces_aggregate_pass_evidence() -> None:
    policy = load_capacity_policy()
    sample = valid_sample(policy)

    evidence = evaluate_capacity(policy, sample)

    assert evidence.classification is CapacityClassification.PASSED
    assert evidence.reason_codes == ("BOUNDED_SYNTHETIC_TARGETS_MET",)
    assert evidence.throughput_requests_per_second == Decimal("2")
    assert evidence.total_cost_usd == Decimal("1.20")
    assert evidence.cost_per_successful_request_usd == Decimal("0.006")
    assert evidence.production_capacity_claimed is False
    assert evidence.live_execution == "NOT_AUTHORIZED"


def test_latency_queue_failure_and_cost_breaches_fail_closed() -> None:
    policy = load_capacity_policy()
    sample = valid_sample(
        policy,
        successful_requests=197,
        timeout_requests=1,
        overload_requests=2,
        latency_milliseconds=(1000,) * 187 + (12000,) * 10,
        peak_queue_depth=2,
        provider_token_cost_usd=Decimal("5.01"),
    )

    evidence = evaluate_capacity(policy, sample)

    assert evidence.classification is CapacityClassification.FAIL
    assert set(evidence.reason_codes) >= {
        "P95_LATENCY_EXCEEDED",
        "P99_LATENCY_EXCEEDED",
        "QUEUE_CAPACITY_EXCEEDED",
        "EVALUATION_COST_EXCEEDED",
        "COST_PER_SUCCESSFUL_REQUEST_EXCEEDED",
        "REQUEST_FAILURES_OBSERVED",
    }


def test_zero_success_stale_price_and_tampered_policy_are_rejected() -> None:
    policy = load_capacity_policy()
    observed_at = valid_sample(policy).observed_at
    cases = (
        valid_sample(
            policy,
            successful_requests=0,
            rejected_requests=200,
            latency_milliseconds=(),
        ),
        valid_sample(policy, pricing_as_of=observed_at - timedelta(hours=25)),
        valid_sample(policy, policy_sha256="0" * 64),
    )

    for sample in cases:
        with pytest.raises(CapacityValidationError):
            evaluate_capacity(policy, sample)


def test_canonical_serialization_and_hash_are_deterministic() -> None:
    policy = load_capacity_policy()
    first = canonical_json(policy)
    second = canonical_json(policy)

    assert first == second
    assert fingerprint(policy) == fingerprint(policy)
    assert "NaN" not in first and "Infinity" not in first
