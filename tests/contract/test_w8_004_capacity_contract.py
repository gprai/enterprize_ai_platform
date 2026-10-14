"""Exact contract tests for the approved W8-004 capacity policy."""

from enterprise_ai_platform.capacity import load_capacity_policy
from enterprise_ai_platform.capacity.models import EngineDecision, EvidenceScope


def test_policy_contains_exact_capacity_latency_scaling_and_cost_contracts() -> None:
    policy = load_capacity_policy()

    assert policy.feature_ids == ("CAP-001", "COST-005")
    assert policy.region == "ap-southeast-1"
    assert policy.evidence_scope is EvidenceScope.OFFLINE_SYNTHETIC_ONLY
    assert policy.demand.concurrency_levels == (1, 4, 8)
    assert policy.demand.warmup_requests == 20
    assert policy.demand.measured_requests_per_level == 200
    assert policy.demand.assumed_input_tokens_per_request == 2048
    assert policy.demand.assumed_output_tokens_per_request == 256
    assert policy.demand.sustained_input_tokens_per_second == 2048
    assert policy.demand.spike_input_tokens_per_second == 6144
    assert policy.latency.p95_milliseconds_less_than == 4000
    assert policy.latency.p99_milliseconds_less_than == 10000
    assert policy.latency.request_timeout_seconds == 25
    assert policy.compute.per_pod_inflight_requests == 4
    assert policy.compute.queue_capacity == 0
    assert (policy.compute.minimum_replicas, policy.compute.maximum_replicas) == (2, 4)
    assert (policy.scaling.cpu_target_percent, policy.scaling.memory_target_percent) == (70, 75)
    assert policy.scaling.scale_down_stabilization_seconds == 300
    assert policy.scaling.pod_disruption_max_unavailable == 1
    assert policy.cost.monthly_budget_usd == 60
    assert policy.cost.maximum_paid_evaluation_usd == 5
    assert policy.cost.cost_per_successful_request_ceiling == "OWNER_BINDING_REQUIRED"


def test_optional_engines_are_never_default_co_deployments() -> None:
    policy = load_capacity_policy()
    decisions = {item.engine: item.decision for item in policy.serving_engines}

    assert decisions == {
        "bedrock": EngineDecision.SELECTED,
        "sagemaker_realtime": EngineDecision.CONDITIONAL_NOT_SELECTED,
        "eks_model_serving": EngineDecision.CONDITIONAL_NOT_SELECTED,
        "karpenter": EngineDecision.CONDITIONAL_NOT_SELECTED,
        "ray_serve": EngineDecision.NOT_ADOPTED,
        "triton": EngineDecision.NOT_ADOPTED,
    }
    assert policy.live_execution == "NOT_AUTHORIZED"
    assert policy.provisioning == "NOT_RUN"
