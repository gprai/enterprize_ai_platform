"""Business scenarios for W8-004 bounded capacity and cost decisions."""

from enterprise_ai_platform.capacity import (
    CapacityClassification,
    evaluate_capacity,
    load_capacity_policy,
)
from enterprise_ai_platform.capacity.models import EngineDecision
from tests.fakes.w8_004_capacity import valid_sample


def test_controlled_weight_scenario_proves_only_synthetic_capacity() -> None:
    policy = load_capacity_policy()
    evidence = evaluate_capacity(policy, valid_sample(policy))

    assert evidence.classification is CapacityClassification.PASSED
    assert evidence.production_capacity_claimed is False
    assert policy.evidence_scope == "offline_synthetic_only"


def test_cold_start_saturation_dependency_and_safe_termination_are_explicit() -> None:
    policy = load_capacity_policy()
    evidence = evaluate_capacity(
        policy,
        valid_sample(
            policy,
            successful_requests=196,
            overload_requests=1,
            timeout_requests=1,
            dependency_failure_requests=2,
            latency_milliseconds=(1000,) * 196,
            cold_start_seconds=121,
            scale_out_seconds=121,
            scale_in_seconds=299,
            unschedulable_pods=1,
            terminated_safely=False,
        ),
    )

    assert evidence.classification is CapacityClassification.FAIL
    assert set(evidence.reason_codes) >= {
        "COLD_START_EXCEEDED",
        "SCALE_OUT_EXCEEDED",
        "SCALE_IN_TOO_FAST",
        "CAPACITY_EXHAUSTED",
        "UNSAFE_TERMINATION",
        "REQUEST_FAILURES_OBSERVED",
    }


def test_specialized_serving_lanes_remain_unselected_without_measured_need() -> None:
    decisions = {item.engine: item.decision for item in load_capacity_policy().serving_engines}

    assert decisions["ray_serve"] is EngineDecision.NOT_ADOPTED
    assert decisions["triton"] is EngineDecision.NOT_ADOPTED
    assert decisions["karpenter"] is EngineDecision.CONDITIONAL_NOT_SELECTED
