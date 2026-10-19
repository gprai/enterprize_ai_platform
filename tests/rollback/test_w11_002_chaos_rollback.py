"""W11-002 local compensation is distinct from application/cloud rollback."""

from pathlib import Path

from tests.fakes.w11_002_chaos import FakeClock, RecordingFault, RecordingObserver, observations

from enterprise_ai_platform.chaos import (
    DEFAULT_CHAOS_POLICY_PATH,
    load_chaos_policy,
    run_local_rehearsal,
)
from enterprise_ai_platform.telemetry.ai_reliability import DecisionStatus

ROOT = Path(__file__).resolve().parents[2]


def test_observation_failure_still_restores_exact_local_fault() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    base = observations(policy, "bedrock_timeout")

    class FailingObserver(RecordingObserver):
        def sample(self, phase: str):  # type: ignore[no-untyped-def]
            if phase == "after":
                raise ValueError("protected synthetic payload must not be emitted")
            return super().sample(phase)

    target = RecordingFault()
    result = run_local_rehearsal(
        policy,
        "bedrock_timeout",
        fault=target,
        observer=FailingObserver(base.before, base.after),
        clock=FakeClock(),
    )
    assert result.local_control_status is DecisionStatus.FAIL
    assert result.sli_status is DecisionStatus.INDETERMINATE
    assert result.recovery_status is DecisionStatus.PASS
    assert result.residue_status is DecisionStatus.PASS
    assert result.stop_reason == "local_observation_or_fault_failed"
    assert target.events == ["inject", "restore"]


def test_failed_restore_blocks_pass_and_preserves_residue() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    target = RecordingFault(restore_fails=True)
    result = run_local_rehearsal(
        policy,
        "bedrock_timeout",
        fault=target,
        observer=observations(policy, "bedrock_timeout"),
        clock=FakeClock(),
    )
    assert result.local_control_status is DecisionStatus.FAIL
    assert result.recovery_status is DecisionStatus.FAIL
    assert result.residue_status is DecisionStatus.FAIL
    assert result.live_status == "NOT RUN"
