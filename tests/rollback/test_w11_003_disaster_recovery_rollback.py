"""W11-003 proves failure preservation, not live operational rollback."""

from pathlib import Path

from tests.fakes.w11_003_disaster_recovery import (
    FakeClock,
    RecordingTarget,
    RecordingVerifier,
    asset,
    auth,
    plan,
)

from enterprise_ai_platform.disaster_recovery import (
    DEFAULT_RECOVERY_POLICY_PATH,
    RecoveryScope,
    RecoveryStatus,
    load_recovery_policy,
    run_local_rehearsal,
)

ROOT = Path(__file__).resolve().parents[2]


def test_substituted_candidate_fails_identity_and_preserves_original_plan() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    value = plan(policy)
    target = RecordingTarget(
        substitute=asset(RecoveryScope.OPENSEARCH_INDEX, artifact="substituted")
    )
    result = run_local_rehearsal(
        policy,
        value,
        auth_context=auth(),
        target=target,
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert result.identity_status is RecoveryStatus.FAIL
    assert result.native_status is RecoveryStatus.NOT_RUN
    assert result.local_contract_status is RecoveryStatus.FAIL
    assert result.source_identity_sha256 == value.source.artifact_identity_sha256
    assert target.events == ["INDEX_REBUILD", "CLEANUP"]


def test_partial_execution_is_indeterminate_and_never_reports_live_restore() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    result = run_local_rehearsal(
        policy,
        plan(policy),
        auth_context=auth(),
        target=RecordingTarget(execute_fails=True),
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert result.identity_status is RecoveryStatus.INDETERMINATE
    assert result.local_contract_status is RecoveryStatus.INDETERMINATE
    assert result.live_status == "NOT RUN"


def test_cleanup_failure_blocks_pass_and_preserves_failed_residue() -> None:
    policy = load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)
    result = run_local_rehearsal(
        policy,
        plan(policy),
        auth_context=auth(),
        target=RecordingTarget(cleanup_fails=True),
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert result.cleanup_status is RecoveryStatus.FAIL
    assert result.local_contract_status is RecoveryStatus.FAIL
    assert result.safe_reason_code == "RECOVERY_CLEANUP_FAILED"
