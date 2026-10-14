"""Composition checks across W8-004 policy, serving, orchestration, and K8s controls."""

from pathlib import Path

import yaml

from enterprise_ai_platform.capacity import load_capacity_policy

ROOT = Path(__file__).resolve().parents[2]


def _yaml(path: str) -> dict[str, object]:
    value = yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_capacity_contract_composes_with_existing_serving_and_failure_limits() -> None:
    policy = load_capacity_policy(ROOT / "configs/capacity/inference-capacity-cost-policy.yaml")
    serving = _yaml("configs/serving/model-serving-routing.yaml")
    orchestration = _yaml("configs/orchestration/async-workflow-policy.yaml")

    assert serving["foundation_provider"] == "bedrock"
    assert serving["request_timeout_seconds"] == policy.latency.request_timeout_seconds
    assert serving["maximum_concurrent_calls"] == policy.compute.per_pod_inflight_requests
    assert serving["autoscaling_min_replicas"] == policy.compute.minimum_replicas
    assert serving["autoscaling_max_replicas"] == policy.compute.maximum_replicas
    assert serving["circuit_breaker_failure_threshold"] == (
        policy.failure.circuit_breaker_failure_threshold
    )
    assert orchestration["provider_circuit"]["failure_threshold"] == (
        policy.failure.circuit_breaker_failure_threshold
    )
    assert orchestration["live_execution"] == policy.live_execution


def test_capacity_contract_extends_existing_hpa_and_pdb_in_place() -> None:
    policy = load_capacity_policy(ROOT / "configs/capacity/inference-capacity-cost-policy.yaml")
    hpa = _yaml("deploy/k8s/hpa.yaml")
    pdb = _yaml("deploy/k8s/pdb.yaml")

    assert hpa["spec"]["minReplicas"] == policy.compute.minimum_replicas
    assert hpa["spec"]["maxReplicas"] == policy.compute.maximum_replicas
    assert [metric["resource"]["name"] for metric in hpa["spec"]["metrics"]] == [
        "cpu",
        "memory",
    ]
    assert hpa["spec"]["behavior"]["scaleDown"]["stabilizationWindowSeconds"] == (
        policy.scaling.scale_down_stabilization_seconds
    )
    assert pdb["spec"]["maxUnavailable"] == policy.scaling.pod_disruption_max_unavailable
    assert "minAvailable" not in pdb["spec"]
