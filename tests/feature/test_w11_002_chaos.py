"""W11-002 dependency and failure-story acceptance, synthetic only."""

from pathlib import Path

import pytest

from enterprise_ai_platform.chaos import (
    DEFAULT_CHAOS_POLICY_PATH,
    load_chaos_policy,
    run_local_rehearsal,
)
from enterprise_ai_platform.telemetry.ai_reliability import DecisionStatus
from tests.fakes.w11_002_chaos import FakeClock, RecordingFault, observations

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("scenario_id", "domain", "fault"),
    [
        ("eks_pod_loss", "eks", "pod_loss"),
        ("eks_node_loss", "eks", "node_loss_simulated"),
        ("bedrock_timeout", "bedrock", "timeout"),
        ("bedrock_throttle", "bedrock", "throttle"),
        ("opensearch_unavailable", "opensearch", "unavailable"),
        ("opensearch_stale", "opensearch", "stale_response"),
        ("s3_unavailable", "s3", "unavailable"),
        ("s3_partial", "s3", "partial_failure"),
        ("inference_timeout", "inference", "timeout"),
        ("inference_partial", "inference", "partial_failure"),
        ("network_timeout", "network", "timeout"),
        ("telemetry_loss", "telemetry", "exporter_loss"),
        ("unsafe_state", "safety", "unsafe_state"),
    ],
)
def test_named_fault_proves_detection_abort_and_recovery(
    scenario_id: str, domain: str, fault: str
) -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    scenario = next(item for item in policy.scenarios if item.id == scenario_id)
    assert (scenario.domain, scenario.fault) == (domain, fault)
    result = run_local_rehearsal(
        policy,
        scenario_id,
        fault=RecordingFault(),
        observer=observations(policy, scenario_id),
        clock=FakeClock(),
    )
    assert result.local_control_status is DecisionStatus.PASS
    assert result.recovery_status is DecisionStatus.PASS
    assert result.residue_status is DecisionStatus.PASS
    assert result.live_status == "NOT RUN"
    if scenario_id == "telemetry_loss":
        assert result.sli_status is DecisionStatus.INDETERMINATE
    else:
        assert result.sli_status is DecisionStatus.FAIL


def test_synthetic_availability_burn_is_not_live_slo_attainment() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    result = run_local_rehearsal(
        policy,
        "eks_pod_loss",
        fault=RecordingFault(),
        observer=observations(policy, "eks_pod_loss"),
        clock=FakeClock(),
    )
    assert result.burn_status is DecisionStatus.FAIL
    assert result.synthetic_alert_status is DecisionStatus.PASS
    assert result.error_budget_remaining_ratio == 0
    assert result.live_status == "NOT RUN"
