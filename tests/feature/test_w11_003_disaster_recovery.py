"""DR-001/RPO-001 source-contract acceptance without readiness inflation."""

from pathlib import Path

import pytest

from enterprise_ai_platform.disaster_recovery import (
    DEFAULT_RECOVERY_POLICY_PATH,
    RecoveryOperation,
    RecoveryPolicy,
    RecoveryScope,
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


@pytest.fixture(scope="module")
def policy() -> RecoveryPolicy:
    return load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)


@pytest.mark.parametrize("scope", list(RecoveryScope))
def test_each_recovery_boundary_is_identity_and_tenant_verified(
    policy: RecoveryPolicy, scope: RecoveryScope
) -> None:
    operation = (
        RecoveryOperation.INDEX_REBUILD
        if scope is RecoveryScope.OPENSEARCH_INDEX
        else RecoveryOperation.RESTORE
    )
    result = run_local_rehearsal(
        policy,
        plan(policy, operation=operation, scope=scope),
        auth_context=auth(),
        target=RecordingTarget(),
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert result.local_contract_status is RecoveryStatus.PASS
    assert tuple(item.kind for item in result.verifications) == (
        "IDENTITY",
        "INTEGRITY",
        "AUTHORIZATION",
        "HEALTH",
        "RESIDUE",
    )
    assert result.multi_region_readiness == "NOT_ESTABLISHED"


@pytest.mark.parametrize("status", [RecoveryStatus.FAIL, RecoveryStatus.INDETERMINATE])
def test_incomplete_native_verification_never_claims_recovery(
    policy: RecoveryPolicy, status: RecoveryStatus
) -> None:
    result = run_local_rehearsal(
        policy,
        plan(policy),
        auth_context=auth(),
        target=RecordingTarget(),
        verifier=RecordingVerifier(status=status),
        clock=FakeClock(),
    )
    assert result.native_status is status
    assert result.local_contract_status is status
    assert result.live_status == "NOT RUN"
    assert result.multi_region_readiness == "NOT_ESTABLISHED"


def test_targets_are_not_achieved_multi_region_evidence(policy: RecoveryPolicy) -> None:
    assert policy.objectives.target_rpo_seconds == 24 * 60 * 60
    assert policy.objectives.target_rto_seconds == 8 * 60 * 60
    assert policy.secondary_account_id is None
    assert policy.secondary_region is None
    assert policy.live_execution_status == "NOT RUN"
