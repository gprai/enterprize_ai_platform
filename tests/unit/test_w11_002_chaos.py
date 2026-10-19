"""Unit proof of bounded W11-002 synthetic fault handling."""

from pathlib import Path

import pytest

from enterprise_ai_platform.chaos import (
    DEFAULT_CHAOS_POLICY_PATH,
    ChaosPolicy,
    InMemoryFaultTarget,
    load_chaos_policy,
    run_local_rehearsal,
)
from enterprise_ai_platform.telemetry.ai_reliability import DecisionStatus
from tests.fakes.w11_002_chaos import FakeClock, RecordingFault, changed_observation, observations

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def policy() -> ChaosPolicy:
    return load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)


@pytest.mark.parametrize(
    "scenario_id",
    [
        "eks_pod_loss",
        "eks_node_loss",
        "bedrock_timeout",
        "bedrock_throttle",
        "opensearch_unavailable",
        "opensearch_stale",
        "s3_unavailable",
        "s3_partial",
        "inference_timeout",
        "inference_partial",
        "network_timeout",
        "telemetry_loss",
        "unsafe_state",
    ],
)
def test_each_synthetic_fault_is_detected_and_restored(
    policy: ChaosPolicy, scenario_id: str
) -> None:
    target = RecordingFault()
    result = run_local_rehearsal(
        policy,
        scenario_id,
        fault=target,
        observer=observations(policy, scenario_id),
        clock=FakeClock(),
    )
    assert result.local_control_status is DecisionStatus.PASS
    assert result.recovery_status is DecisionStatus.PASS
    assert result.residue_status is DecisionStatus.PASS
    assert result.live_status == "NOT RUN"
    assert result.injected_count == result.restored_count == 1
    assert target.events == ["inject", "restore"]


def test_telemetry_loss_never_becomes_measured_sli_or_delivered_alert(
    policy: ChaosPolicy,
) -> None:
    result = run_local_rehearsal(
        policy,
        "telemetry_loss",
        fault=RecordingFault(),
        observer=observations(policy, "telemetry_loss"),
        clock=FakeClock(),
    )
    assert result.stop_reason == "missing_telemetry"
    assert result.sli_status is DecisionStatus.INDETERMINATE
    assert result.synthetic_alert_status is DecisionStatus.NOT_RUN


def test_unsafe_state_is_a_failed_safety_observation_not_a_healthy_sli(
    policy: ChaosPolicy,
) -> None:
    result = run_local_rehearsal(
        policy,
        "unsafe_state",
        fault=RecordingFault(),
        observer=observations(policy, "unsafe_state"),
        clock=FakeClock(),
    )
    assert result.stop_reason == "unsafe_state"
    assert result.sli_status is DecisionStatus.FAIL


def test_missing_preflight_telemetry_prevents_fault_injection(
    policy: ChaosPolicy,
) -> None:
    observer = observations(policy, "bedrock_timeout")
    observer.before = changed_observation(observer.before, telemetry_available=False)
    target = RecordingFault()
    result = run_local_rehearsal(
        policy, "bedrock_timeout", fault=target, observer=observer, clock=FakeClock()
    )
    assert result.stop_reason == "missing_telemetry"
    assert result.injected_count == 0
    assert target.events == []
    assert result.sli_status is DecisionStatus.INDETERMINATE
    assert result.local_control_status is DecisionStatus.FAIL


def test_missing_synthetic_alert_prevents_local_pass(policy: ChaosPolicy) -> None:
    observer = observations(policy, "bedrock_timeout")
    observer.after = changed_observation(observer.after, synthetic_alert_observed=False)
    result = run_local_rehearsal(
        policy,
        "bedrock_timeout",
        fault=RecordingFault(),
        observer=observer,
        clock=FakeClock(),
    )
    assert result.synthetic_alert_status is DecisionStatus.FAIL
    assert result.local_control_status is DecisionStatus.FAIL


def test_unknown_scenario_cannot_inject(policy: ChaosPolicy) -> None:
    target = InMemoryFaultTarget()
    with pytest.raises(ValueError, match="not eligible"):
        run_local_rehearsal(
            policy,
            "production-node-delete",
            fault=target,
            observer=observations(policy, "eks_pod_loss"),
            clock=FakeClock(),
        )
    assert target.injected_count == 0
