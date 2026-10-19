"""Deterministic, content-free W11-003 recovery fixtures."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

from enterprise_ai_platform.disaster_recovery import (
    InMemoryNativeVerifier,
    InMemoryRecoveryTarget,
    NativeVerification,
    RecoveryAssetIdentity,
    RecoveryOperation,
    RecoveryPlan,
    RecoveryPolicy,
    RecoveryScope,
    RecoveryStatus,
    canonical_sha256,
)
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role

NOW = datetime(2026, 10, 20, 4, 0, tzinfo=UTC)


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class FakeClock:
    def __init__(self) -> None:
        self.elapsed = 0.0
        self.utc_now = NOW
        self.is_cancelled = False

    def now_utc(self) -> datetime:
        return self.utc_now

    def monotonic(self) -> float:
        return self.elapsed

    def cancelled(self) -> bool:
        return self.is_cancelled

    def advance(self, seconds: float) -> None:
        self.elapsed += seconds
        self.utc_now += timedelta(seconds=seconds)


def asset(
    scope: RecoveryScope,
    *,
    artifact: str,
    tenant_id: str = "tenant-a",
    recovery_point_at: datetime = NOW - timedelta(hours=1),
) -> RecoveryAssetIdentity:
    value: dict[str, object] = {
        "scope": scope,
        "tenant_id": tenant_id,
        "classification": Classification.INTERNAL,
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "source_identity_sha256": digest("immutable-source"),
        "artifact_identity_sha256": digest(artifact),
        "kms_identity_sha256": digest("kms"),
        "iam_identity_sha256": digest("iam"),
        "recovery_point_at": recovery_point_at,
    }
    if scope in {RecoveryScope.S3_GOVERNED_SOURCE, RecoveryScope.MODEL_ARTIFACT}:
        value["object_version_id"] = "version-1"
    elif scope is RecoveryScope.OPENSEARCH_INDEX:
        value["collection_spec_sha256"] = digest("collection-spec")
    elif scope is RecoveryScope.MODEL_REGISTRY:
        value["registry_export_sha256"] = digest("registry-export")
    else:
        value["state_lineage"] = "lineage-1"
        value["state_serial"] = 12
    return RecoveryAssetIdentity.model_validate(value)


def plan(
    policy: RecoveryPolicy,
    *,
    operation: RecoveryOperation = RecoveryOperation.INDEX_REBUILD,
    scope: RecoveryScope = RecoveryScope.OPENSEARCH_INDEX,
) -> RecoveryPlan:
    return RecoveryPlan(
        operation_id="w11-003-test-operation",
        operation=operation,
        scope=scope,
        source=asset(scope, artifact="source"),
        expected_target=asset(scope, artifact="candidate"),
        approval_reference_sha256=digest("approval"),
        policy_sha256=canonical_sha256(policy),
        requested_at=NOW,
        deadline_at=NOW + timedelta(seconds=30),
    )


def auth(*, tenant_id: str = "tenant-a", role: Role = Role.ADMIN) -> AuthContext:
    return AuthContext(
        subject_id="w11-003-owner",
        tenant_id=tenant_id,
        roles=frozenset({role}),
        clearance=Classification.INTERNAL,
        expires_at=NOW + timedelta(minutes=5),
    )


class RecordingTarget(InMemoryRecoveryTarget):
    def __init__(
        self,
        *,
        substitute: RecoveryAssetIdentity | None = None,
        execute_fails: bool = False,
        cleanup_fails: bool = False,
    ) -> None:
        super().__init__()
        self.substitute = substitute
        self.execute_fails = execute_fails
        self.cleanup_fails = cleanup_fails
        self.events: list[str] = []

    def execute(self, plan: RecoveryPlan) -> RecoveryAssetIdentity:
        self.events.append(plan.operation.value)
        if self.execute_fails:
            raise ValueError("synthetic execution failed")
        candidate = super().execute(plan)
        return self.substitute or candidate

    def cleanup(self) -> None:
        self.events.append("CLEANUP")
        if self.cleanup_fails:
            raise ValueError("synthetic cleanup failed")
        super().cleanup()


class RecordingVerifier(InMemoryNativeVerifier):
    def __init__(self, *, status: RecoveryStatus = RecoveryStatus.PASS) -> None:
        self.status = status
        self.calls = 0

    def verify(
        self, plan: RecoveryPlan, candidate: RecoveryAssetIdentity
    ) -> tuple[NativeVerification, ...]:
        self.calls += 1
        values = super().verify(plan, candidate)
        if self.status is RecoveryStatus.PASS:
            return values
        return tuple(item.model_copy(update={"status": self.status}) for item in values)
