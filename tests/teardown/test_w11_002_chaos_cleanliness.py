"""W11-002 proves only in-memory residue, never cloud cleanliness."""

from pathlib import Path

from enterprise_ai_platform.chaos import (
    DEFAULT_CHAOS_POLICY_PATH,
    load_chaos_policy,
    run_local_rehearsal,
)
from enterprise_ai_platform.telemetry.ai_reliability import DecisionStatus
from tests.fakes.w11_002_chaos import FakeClock, RecordingFault, observations

ROOT = Path(__file__).resolve().parents[2]


def test_successful_rehearsal_has_no_active_fault_or_second_restore() -> None:
    policy = load_chaos_policy(ROOT / DEFAULT_CHAOS_POLICY_PATH, repository_root=ROOT)
    target = RecordingFault()
    result = run_local_rehearsal(
        policy,
        "network_timeout",
        fault=target,
        observer=observations(policy, "network_timeout"),
        clock=FakeClock(),
    )
    assert target.is_clean()
    assert target.injected_count == 1
    assert target.restored_count == 1
    assert result.residue_status is DecisionStatus.PASS
    target.restore()
    assert target.restored_count == 1


def test_no_local_cleanup_result_is_misreported_as_cloud_proof() -> None:
    source = (ROOT / "src/enterprise_ai_platform/chaos.py").read_text(encoding="utf-8")
    assert 'live_status: Literal["NOT RUN"]' in source
    assert "native_resource_status" not in source
