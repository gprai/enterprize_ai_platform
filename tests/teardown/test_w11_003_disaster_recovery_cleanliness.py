"""W11-003 cleanliness is isolated memory-only candidate cleanup."""

from pathlib import Path

from enterprise_ai_platform.disaster_recovery import (
    DEFAULT_RECOVERY_POLICY_PATH,
    RecoveryStatus,
    load_recovery_policy,
    run_local_rehearsal,
)
from tests.fakes.w11_003_disaster_recovery import (
    FakeClock,
    RecordingTarget,
    RecordingVerifier,
    auth,
    plan,
)

ROOT = Path(__file__).resolve().parents[2]


def test_successful_rehearsal_cleans_exactly_one_isolated_candidate() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    target = RecordingTarget()
    result = run_local_rehearsal(
        policy,
        plan(policy),
        auth_context=auth(),
        target=target,
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert target.is_clean()
    assert target.execute_count == 1
    assert target.cleanup_count == 1
    assert result.cleanup_status is RecoveryStatus.PASS
    target.cleanup()
    assert target.cleanup_count == 1


def test_source_never_reads_or_rewrites_protected_terraform_state() -> None:
    source = (ROOT / "src/enterprise_ai_platform/disaster_recovery.py").read_text(encoding="utf-8")
    cli = (ROOT / "tools/recoveryctl.py").read_text(encoding="utf-8")
    assert "infra/bootstrap/terraform.tfstate" not in source
    assert "infra/bootstrap/terraform.tfstate" not in cli
    assert "write_bytes(" not in source
    assert "write_text(" not in source


def test_local_cleanup_is_not_cloud_teardown_evidence() -> None:
    source = (ROOT / "src/enterprise_ai_platform/disaster_recovery.py").read_text(encoding="utf-8")
    assert 'live_status: Literal["NOT RUN"]' in source
    assert 'multi_region_readiness: Literal["NOT_ESTABLISHED"]' in source
