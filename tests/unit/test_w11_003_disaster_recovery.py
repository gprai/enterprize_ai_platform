"""Unit proof for bounded W11-003 recovery evidence."""

from datetime import timedelta
from pathlib import Path

import pytest

from enterprise_ai_platform.disaster_recovery import (
    DEFAULT_RECOVERY_POLICY_PATH,
    RecoveryOperation,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryScope,
    RecoveryStatus,
    canonical_sha256,
    load_recovery_policy,
    run_local_rehearsal,
)
from tests.fakes.w11_003_disaster_recovery import (
    FakeClock,
    RecordingTarget,
    RecordingVerifier,
    asset,
    auth,
    digest,
    plan,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def policy() -> RecoveryPolicy:
    return load_recovery_policy(ROOT / DEFAULT_RECOVERY_POLICY_PATH, repository_root=ROOT)


@pytest.mark.parametrize(
    ("operation", "scope"),
    [
        (RecoveryOperation.BACKUP, RecoveryScope.S3_GOVERNED_SOURCE),
        (RecoveryOperation.RESTORE, RecoveryScope.MODEL_ARTIFACT),
        (RecoveryOperation.INDEX_REBUILD, RecoveryScope.OPENSEARCH_INDEX),
        (RecoveryOperation.ROLLBACK, RecoveryScope.MODEL_REGISTRY),
        (RecoveryOperation.TEARDOWN, RecoveryScope.TERRAFORM_STATE),
    ],
)
def test_each_operation_is_distinct_and_locally_evidence_bound(
    policy: RecoveryPolicy, operation: RecoveryOperation, scope: RecoveryScope
) -> None:
    value = plan(policy, operation=operation, scope=scope)
    target = RecordingTarget()
    evidence = run_local_rehearsal(
        policy,
        value,
        auth_context=auth(),
        target=target,
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert evidence.local_contract_status is RecoveryStatus.PASS
    assert evidence.rpo_status is RecoveryStatus.PASS
    assert evidence.rto_status is RecoveryStatus.PASS
    assert evidence.live_status == "NOT RUN"
    assert evidence.multi_region_readiness == "NOT_ESTABLISHED"
    assert target.events == [operation.value, "CLEANUP"]


def test_stale_recovery_point_fails_rpo_without_changing_live_status(
    policy: RecoveryPolicy,
) -> None:
    value = plan(policy)
    stale = asset(
        RecoveryScope.OPENSEARCH_INDEX,
        artifact="source",
        recovery_point_at=value.requested_at - timedelta(seconds=86401),
    )
    changed = RecoveryPlan.model_validate(
        {**value.model_dump(), "source": stale.model_dump()}, strict=True
    )
    evidence = run_local_rehearsal(
        policy,
        changed,
        auth_context=auth(),
        target=RecordingTarget(),
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert evidence.rpo_status is RecoveryStatus.FAIL
    assert evidence.local_contract_status is RecoveryStatus.FAIL
    assert evidence.multi_region_readiness == "NOT_ESTABLISHED"


def test_cross_tenant_or_non_admin_context_denies_before_execution(
    policy: RecoveryPolicy,
) -> None:
    target = RecordingTarget()
    evidence = run_local_rehearsal(
        policy,
        plan(policy),
        auth_context=auth(tenant_id="tenant-b"),
        target=target,
        verifier=RecordingVerifier(),
        clock=FakeClock(),
    )
    assert evidence.authorization_status is RecoveryStatus.FAIL
    assert evidence.local_contract_status is RecoveryStatus.FAIL
    assert target.events == []


def test_cancellation_before_recovery_prevents_candidate_creation(
    policy: RecoveryPolicy,
) -> None:
    clock = FakeClock()
    clock.is_cancelled = True
    target = RecordingTarget()
    evidence = run_local_rehearsal(
        policy,
        plan(policy),
        auth_context=auth(),
        target=target,
        verifier=RecordingVerifier(),
        clock=clock,
    )
    assert evidence.safe_reason_code == "CANCELLED_BEFORE_RECOVERY"
    assert evidence.local_contract_status is RecoveryStatus.INDETERMINATE
    assert target.events == []


def test_policy_and_plan_identity_are_canonical_and_newline_terminated(
    policy: RecoveryPolicy,
) -> None:
    value = plan(policy)
    assert len(canonical_sha256(policy)) == 64
    assert value.policy_sha256 == canonical_sha256(policy)
    assert value.approval_reference_sha256 == digest("approval")


def test_index_rebuild_rejects_wrong_scope_or_same_candidate(
    policy: RecoveryPolicy,
) -> None:
    value = plan(policy)
    with pytest.raises(ValueError, match="OpenSearch"):
        RecoveryPlan.model_validate(
            {
                **value.model_dump(),
                "scope": RecoveryScope.S3_GOVERNED_SOURCE,
                "source": asset(RecoveryScope.S3_GOVERNED_SOURCE, artifact="source").model_dump(),
                "expected_target": asset(
                    RecoveryScope.S3_GOVERNED_SOURCE, artifact="candidate"
                ).model_dump(),
            },
            strict=True,
        )
    with pytest.raises(ValueError, match="distinct"):
        RecoveryPlan.model_validate(
            {
                **value.model_dump(),
                "expected_target": value.source.model_dump(),
            },
            strict=True,
        )
