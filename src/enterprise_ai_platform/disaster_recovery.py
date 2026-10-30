"""W11-003 identity-bound, offline disaster-recovery evidence contracts."""

from __future__ import annotations

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal, Protocol

import yaml  # type: ignore[import-untyped]
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)
from yaml.tokens import AliasToken, AnchorToken  # type: ignore[import-untyped]

from enterprise_ai_platform.retrieval.models import (
    CLASSIFICATION_RANK,
    AuthContext,
    Classification,
    Role,
)

RECOVERY_SCHEMA_VERSION: Final = "w11-003.disaster-recovery.v1"
PLAN_SCHEMA_VERSION: Final = "w11-003.recovery-plan.v1"
EVIDENCE_SCHEMA_VERSION: Final = "w11-003.recovery-evidence.v1"
DEFAULT_RECOVERY_POLICY_PATH: Final = Path("configs/recovery/disaster-recovery.yaml")
MAXIMUM_POLICY_BYTES: Final = 131_072
SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
SAFE_ID_PATTERN: Final = r"^[a-z0-9][a-z0-9-]{0,127}$"
ACCOUNT_PATTERN: Final = r"^[0-9]{12}$"
PRIMARY_ACCOUNT_ID: Final = "526338061652"
PRIMARY_REGION: Final = "ap-southeast-1"

SOURCE_PATHS: Final = {
    "data_foundation_sha256": Path("configs/ingestion/governed-data-foundation.yaml"),
    "privacy_lifecycle_config_sha256": Path("configs/ingestion/privacy-retention-lifecycle.yaml"),
    "ingestion_governance_sha256": Path("src/enterprise_ai_platform/ingestion/governance.py"),
    "ingestion_privacy_lifecycle_sha256": Path(
        "src/enterprise_ai_platform/ingestion/privacy_lifecycle.py"
    ),
    "retrieval_models_sha256": Path("src/enterprise_ai_platform/retrieval/models.py"),
    "opensearch_adapter_sha256": Path(
        "src/enterprise_ai_platform/retrieval/adapters/opensearch.py"
    ),
    "model_registry_models_sha256": Path("src/enterprise_ai_platform/model_registry/models.py"),
    "model_registry_contracts_sha256": Path(
        "src/enterprise_ai_platform/model_registry/contracts.py"
    ),
    "model_registry_store_sha256": Path("src/enterprise_ai_platform/model_registry/registry.py"),
    "lifecycle_models_sha256": Path("tools/platformctl/lifecycle_models.py"),
    "lifecycle_io_sha256": Path("tools/platformctl/lifecycle_io.py"),
    "lifecycle_rollback_sha256": Path("tools/platformctl/rollback.py"),
    "bootstrap_main_sha256": Path("infra/bootstrap/main.tf"),
    "bootstrap_variables_sha256": Path("infra/bootstrap/variables.tf"),
    "backend_example_sha256": Path("infra/environments/sandbox/backend.hcl.example"),
    "sandbox_variables_sha256": Path("infra/environments/sandbox/variables.tf"),
    "storage_module_sha256": Path("infra/modules/storage/main.tf"),
    "opensearch_module_sha256": Path("infra/modules/opensearch/main.tf"),
    "kms_module_sha256": Path("infra/modules/kms/main.tf"),
    "iam_module_sha256": Path("infra/bootstrap/modules/platform-iam/main.tf"),
    "w7_recovery_test_sha256": Path("tests/rollback/test_w7_001_remediation_rollback.py"),
    "terraform_state_boundary_test_sha256": Path("tests/teardown/test_terraform_state_boundary.py"),
}

RECOVERY_SCOPE_ORDER: Final = (
    "TERRAFORM_STATE",
    "S3_GOVERNED_SOURCE",
    "OPENSEARCH_INDEX",
    "MODEL_ARTIFACT",
    "MODEL_REGISTRY",
)
STOP_CONDITIONS: Final = (
    "identity_or_scope_mismatch",
    "tenant_or_authorization_mismatch",
    "state_lineage_or_serial_mismatch",
    "kms_iam_or_routing_identity_mismatch",
    "deadline_or_cancellation",
    "native_verification_incomplete",
    "recovery_or_residue_unverified",
)
VerificationKind = Literal["IDENTITY", "INTEGRITY", "AUTHORIZATION", "HEALTH", "RESIDUE"]

VERIFICATION_ORDER: Final[tuple[VerificationKind, ...]] = (
    "IDENTITY",
    "INTEGRITY",
    "AUTHORIZATION",
    "HEALTH",
    "RESIDUE",
)


class RecoveryStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - status label, never a credential
    FAIL = "FAIL"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


class RecoveryOperation(StrEnum):
    BACKUP = "BACKUP"
    RESTORE = "RESTORE"
    INDEX_REBUILD = "INDEX_REBUILD"
    ROLLBACK = "ROLLBACK"
    TEARDOWN = "TEARDOWN"


class RecoveryScope(StrEnum):
    TERRAFORM_STATE = "TERRAFORM_STATE"
    S3_GOVERNED_SOURCE = "S3_GOVERNED_SOURCE"
    OPENSEARCH_INDEX = "OPENSEARCH_INDEX"
    MODEL_ARTIFACT = "MODEL_ARTIFACT"
    MODEL_REGISTRY = "MODEL_REGISTRY"


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


def _require_utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC")
    return value.astimezone(UTC)


class SourceIdentities(_StrictModel):
    data_foundation_sha256: str = Field(pattern=SHA256_PATTERN)
    privacy_lifecycle_config_sha256: str = Field(pattern=SHA256_PATTERN)
    ingestion_governance_sha256: str = Field(pattern=SHA256_PATTERN)
    ingestion_privacy_lifecycle_sha256: str = Field(pattern=SHA256_PATTERN)
    retrieval_models_sha256: str = Field(pattern=SHA256_PATTERN)
    opensearch_adapter_sha256: str = Field(pattern=SHA256_PATTERN)
    model_registry_models_sha256: str = Field(pattern=SHA256_PATTERN)
    model_registry_contracts_sha256: str = Field(pattern=SHA256_PATTERN)
    model_registry_store_sha256: str = Field(pattern=SHA256_PATTERN)
    lifecycle_models_sha256: str = Field(pattern=SHA256_PATTERN)
    lifecycle_io_sha256: str = Field(pattern=SHA256_PATTERN)
    lifecycle_rollback_sha256: str = Field(pattern=SHA256_PATTERN)
    bootstrap_main_sha256: str = Field(pattern=SHA256_PATTERN)
    bootstrap_variables_sha256: str = Field(pattern=SHA256_PATTERN)
    backend_example_sha256: str = Field(pattern=SHA256_PATTERN)
    sandbox_variables_sha256: str = Field(pattern=SHA256_PATTERN)
    storage_module_sha256: str = Field(pattern=SHA256_PATTERN)
    opensearch_module_sha256: str = Field(pattern=SHA256_PATTERN)
    kms_module_sha256: str = Field(pattern=SHA256_PATTERN)
    iam_module_sha256: str = Field(pattern=SHA256_PATTERN)
    w7_recovery_test_sha256: str = Field(pattern=SHA256_PATTERN)
    terraform_state_boundary_test_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("*", mode="before")
    @classmethod
    def normalize_grouped_sha256(cls, value: object) -> object:
        if isinstance(value, str) and len(value) == 71:
            groups = value.split("-")
            if len(groups) == 8 and all(
                len(group) == 8 and all(character in "0123456789abcdef" for character in group)
                for group in groups
            ):
                return "".join(groups)
        return value


class RecoveryObjectives(_StrictModel):
    target_rpo_seconds: Literal[86400]
    target_rto_seconds: Literal[28800]


class ExecutionBounds(_StrictModel):
    operation_concurrency: Literal[1]
    read_probe_maximum_attempts: Literal[2]
    mutation_retry_count: Literal[0]
    rehearsal_deadline_seconds: Literal[30]
    evidence_retention_days: Literal[180]


class RecoveryPolicy(_StrictModel):
    schema_version: Literal["w11-003.disaster-recovery.v1"]
    prompt_id: Literal["W11-003"]
    feature_ids: tuple[str, ...]
    classification: Literal["source-contract-not-live-evidence"]
    environment: Literal["sandbox"]
    primary_account_id: Literal["526338061652"]
    primary_region: Literal["ap-southeast-1"]
    secondary_account_id: None
    secondary_region: None
    recovery_mode: Literal["COLD_REBUILD"]
    objectives: RecoveryObjectives
    execution: ExecutionBounds
    live_execution_status: Literal["NOT RUN"]
    multi_region_readiness: Literal["NOT_ESTABLISHED"]
    recovery_scopes: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    source_identities: SourceIdentities

    @model_validator(mode="after")
    def require_exact_contract(self) -> RecoveryPolicy:
        if self.feature_ids != ("DR-001", "RPO-001"):
            raise ValueError("recovery feature ownership differs")
        if self.recovery_scopes != RECOVERY_SCOPE_ORDER:
            raise ValueError("recovery scope inventory or order differs")
        if self.stop_conditions != STOP_CONDITIONS:
            raise ValueError("recovery stop conditions differ")
        return self


class RecoveryAssetIdentity(_StrictModel):
    scope: RecoveryScope
    tenant_id: str = Field(pattern=SAFE_ID_PATTERN)
    classification: Classification
    account_id: str = Field(pattern=ACCOUNT_PATTERN)
    region: str = Field(pattern=r"^[a-z]{2}-[a-z]+-[0-9]$")
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    kms_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    iam_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    dns_ingress_identity_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    object_version_id: str | None = Field(default=None, min_length=1, max_length=1024)
    collection_spec_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    registry_export_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    state_lineage: str | None = Field(default=None, min_length=1, max_length=128)
    state_serial: int | None = Field(default=None, ge=0)
    recovery_point_at: datetime

    @field_validator("recovery_point_at")
    @classmethod
    def require_utc_recovery_point(cls, value: datetime) -> datetime:
        return _require_utc(value, "recovery_point_at")

    @model_validator(mode="after")
    def require_scope_identity(self) -> RecoveryAssetIdentity:
        if self.classification not in {Classification.PUBLIC, Classification.INTERNAL}:
            raise ValueError("recovery classification is outside the approved data boundary")
        if self.account_id != PRIMARY_ACCOUNT_ID or self.region != PRIMARY_REGION:
            raise ValueError("source-only recovery identity must remain in the primary boundary")
        state_fields = (self.state_lineage, self.state_serial)
        if self.scope is RecoveryScope.TERRAFORM_STATE:
            if any(value is None for value in state_fields):
                raise ValueError("Terraform recovery requires lineage and serial")
        elif any(value is not None for value in state_fields):
            raise ValueError("state identity is valid only for Terraform recovery")
        requires_version = self.scope in {
            RecoveryScope.S3_GOVERNED_SOURCE,
            RecoveryScope.MODEL_ARTIFACT,
        }
        if requires_version != (self.object_version_id is not None):
            raise ValueError("object-version identity differs from recovery scope")
        if (self.scope is RecoveryScope.OPENSEARCH_INDEX) != (
            self.collection_spec_sha256 is not None
        ):
            raise ValueError("collection identity differs from recovery scope")
        if (self.scope is RecoveryScope.MODEL_REGISTRY) != (
            self.registry_export_sha256 is not None
        ):
            raise ValueError("registry export identity differs from recovery scope")
        return self


class RecoveryPlan(_StrictModel):
    schema_version: Literal["w11-003.recovery-plan.v1"] = PLAN_SCHEMA_VERSION
    operation_id: str = Field(pattern=SAFE_ID_PATTERN)
    operation: RecoveryOperation
    scope: RecoveryScope
    mode: Literal["COLD_REBUILD"] = "COLD_REBUILD"
    source: RecoveryAssetIdentity
    expected_target: RecoveryAssetIdentity
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_at: datetime
    deadline_at: datetime
    execution_status: Literal["NOT RUN"] = "NOT RUN"

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _require_utc(value, "plan timestamp")

    @model_validator(mode="after")
    def require_bounded_distinct_operation(self) -> RecoveryPlan:
        if self.source.scope is not self.scope or self.expected_target.scope is not self.scope:
            raise ValueError("plan and asset scopes differ")
        if self.source.tenant_id != self.expected_target.tenant_id:
            raise ValueError("recovery target tenant differs")
        if self.source.classification is not self.expected_target.classification:
            raise ValueError("recovery target classification differs")
        if self.deadline_at <= self.requested_at:
            raise ValueError("recovery deadline must follow request time")
        if (self.deadline_at - self.requested_at).total_seconds() > 30:
            raise ValueError("local recovery plan exceeds thirty seconds")
        if self.operation is RecoveryOperation.INDEX_REBUILD:
            if self.scope is not RecoveryScope.OPENSEARCH_INDEX:
                raise ValueError("index rebuild requires the OpenSearch scope")
            if (
                self.source.artifact_identity_sha256
                == self.expected_target.artifact_identity_sha256
            ):
                raise ValueError("index rebuild requires a distinct candidate identity")
        if self.operation is RecoveryOperation.RESTORE and (
            self.source.artifact_identity_sha256 == self.expected_target.artifact_identity_sha256
        ):
            raise ValueError("restore requires an isolated target identity")
        return self


class NativeVerification(_StrictModel):
    kind: VerificationKind
    scope: RecoveryScope
    status: RecoveryStatus
    identity_sha256: str = Field(pattern=SHA256_PATTERN)
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,79}$")


class RecoveryEvidence(_StrictModel):
    schema_version: Literal["w11-003.recovery-evidence.v1"] = EVIDENCE_SCHEMA_VERSION
    operation_id: str = Field(pattern=SAFE_ID_PATTERN)
    plan_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    recovery_point_age_seconds: int = Field(ge=0)
    elapsed_seconds: int = Field(ge=0)
    rpo_status: RecoveryStatus
    rto_status: RecoveryStatus
    identity_status: RecoveryStatus
    authorization_status: RecoveryStatus
    native_status: RecoveryStatus
    cleanup_status: RecoveryStatus
    local_contract_status: RecoveryStatus
    live_status: Literal["NOT RUN"] = "NOT RUN"
    multi_region_readiness: Literal["NOT_ESTABLISHED"] = "NOT_ESTABLISHED"
    verifications: tuple[NativeVerification, ...]
    executed_steps: tuple[str, ...]
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,79}$")
    started_at: datetime
    completed_at: datetime

    @field_validator("started_at", "completed_at")
    @classmethod
    def require_utc_evidence_time(cls, value: datetime) -> datetime:
        return _require_utc(value, "evidence timestamp")

    @model_validator(mode="after")
    def require_truthful_result(self) -> RecoveryEvidence:
        kinds = tuple(item.kind for item in self.verifications)
        if self.verifications and kinds != VERIFICATION_ORDER:
            raise ValueError("native verification inventory or order differs")
        required = (
            self.rpo_status,
            self.rto_status,
            self.identity_status,
            self.authorization_status,
            self.native_status,
            self.cleanup_status,
        )
        if self.local_contract_status is RecoveryStatus.PASS and any(
            item is not RecoveryStatus.PASS for item in required
        ):
            raise ValueError("local PASS requires every recovery gate to pass")
        return self


class RecoveryTargetPort(Protocol):
    execute_count: int
    cleanup_count: int

    def execute(self, plan: RecoveryPlan) -> RecoveryAssetIdentity: ...

    def cleanup(self) -> None: ...

    def is_clean(self) -> bool: ...


class NativeVerifierPort(Protocol):
    def verify(
        self, plan: RecoveryPlan, candidate: RecoveryAssetIdentity
    ) -> tuple[NativeVerification, ...]: ...


class ClockPort(Protocol):
    def now_utc(self) -> datetime: ...

    def monotonic(self) -> float: ...

    def cancelled(self) -> bool: ...


class SystemClock:
    def now_utc(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()

    def cancelled(self) -> bool:
        return False


class InMemoryRecoveryTarget:
    """One isolated candidate; no file, provider, network or subprocess boundary."""

    def __init__(self) -> None:
        self.execute_count = 0
        self.cleanup_count = 0
        self._active = False

    def execute(self, plan: RecoveryPlan) -> RecoveryAssetIdentity:
        if self._active or self.execute_count or self.cleanup_count:
            raise ValueError("synthetic recovery target is not eligible")
        self.execute_count = 1
        self._active = True
        return plan.expected_target

    def cleanup(self) -> None:
        if self._active and self.cleanup_count == 0:
            self._active = False
            self.cleanup_count = 1

    def is_clean(self) -> bool:
        return not self._active


class InMemoryNativeVerifier:
    def verify(
        self, plan: RecoveryPlan, candidate: RecoveryAssetIdentity
    ) -> tuple[NativeVerification, ...]:
        identity = canonical_sha256(candidate)
        return tuple(
            NativeVerification(
                kind=kind,
                scope=plan.scope,
                status=RecoveryStatus.PASS,
                identity_sha256=identity,
                safe_reason_code=f"{kind}_VERIFIED",
            )
            for kind in VERIFICATION_ORDER
        )


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: Any, deep: bool = False
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError("duplicate YAML key")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def _read_yaml(path: Path) -> object:
    payload = path.read_bytes()
    if not payload or len(payload) > MAXIMUM_POLICY_BYTES:
        raise ValueError("YAML input is empty or oversized")
    if payload.startswith((b"\xff\xfe", b"\xfe\xff")):
        raise ValueError("YAML input must be UTF-8")
    text = payload.decode("utf-8", errors="strict")
    if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
        raise ValueError("YAML aliases are forbidden")
    loader = _UniqueKeyLoader(text)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def canonical_json_bytes(value: BaseModel | object) -> bytes:
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return (
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
    )


def canonical_sha256(value: BaseModel | object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_recovery_policy(path: Path, *, repository_root: Path) -> RecoveryPolicy:
    root = repository_root.resolve()
    if path.resolve() != (root / DEFAULT_RECOVERY_POLICY_PATH).resolve():
        raise ValueError("recovery policy path differs from the authoritative path")
    try:
        policy = RecoveryPolicy.model_validate(_read_yaml(path), strict=False)
        identities = policy.source_identities.model_dump()
        if tuple(identities) != tuple(SOURCE_PATHS):
            raise ValueError("upstream source inventory or order differs")
        for field, relative in SOURCE_PATHS.items():
            if _file_sha256(root / relative) != identities[field]:
                raise ValueError("upstream source identity differs")
        return policy
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError, TypeError) as error:
        raise ValueError("invalid disaster-recovery policy") from error


def require_recovery_authorized(
    plan: RecoveryPlan, auth_context: AuthContext, *, now: datetime
) -> None:
    checked_now = _require_utc(now, "authorization time")
    if (
        not auth_context.is_active(checked_now)
        or Role.ADMIN not in auth_context.roles
        or auth_context.tenant_id != plan.source.tenant_id
        or CLASSIFICATION_RANK[auth_context.clearance]
        < CLASSIFICATION_RANK[plan.source.classification]
    ):
        raise PermissionError("recovery authorization denied")


def _status_for_verifications(values: tuple[NativeVerification, ...]) -> RecoveryStatus:
    if not values or tuple(item.kind for item in values) != VERIFICATION_ORDER:
        return RecoveryStatus.INDETERMINATE
    if any(item.status is RecoveryStatus.FAIL for item in values):
        return RecoveryStatus.FAIL
    if any(item.status is not RecoveryStatus.PASS for item in values):
        return RecoveryStatus.INDETERMINATE
    return RecoveryStatus.PASS


def _count(value: int) -> int:
    return value


def run_local_rehearsal(
    policy: RecoveryPolicy,
    plan: RecoveryPlan,
    *,
    auth_context: AuthContext,
    target: RecoveryTargetPort,
    verifier: NativeVerifierPort,
    clock: ClockPort,
) -> RecoveryEvidence:
    """Prove the contract with memory-only ports; never restore a real system."""

    if plan.policy_sha256 != canonical_sha256(policy):
        raise ValueError("plan policy identity differs")
    if plan.scope.value not in policy.recovery_scopes:
        raise ValueError("plan scope is outside the recovery policy")
    if target.execute_count or target.cleanup_count or not target.is_clean():
        raise ValueError("local recovery target is not clean")

    started_at = clock.now_utc()
    started = clock.monotonic()
    age = int((started_at - plan.source.recovery_point_at).total_seconds())
    if age < 0:
        raise ValueError("recovery point is in the future")
    plan_identity = canonical_sha256(plan)
    candidate = plan.expected_target
    verifications: tuple[NativeVerification, ...] = ()
    steps: list[str] = ["POLICY_AND_PLAN_VERIFIED"]
    identity_status = RecoveryStatus.NOT_RUN
    authorization_status = RecoveryStatus.NOT_RUN
    native_status = RecoveryStatus.NOT_RUN
    reason = "RECOVERY_NOT_STARTED"

    try:
        if clock.cancelled():
            reason = "CANCELLED_BEFORE_RECOVERY"
        else:
            require_recovery_authorized(plan, auth_context, now=started_at)
            authorization_status = RecoveryStatus.PASS
            steps.append("AUTHORIZATION_VERIFIED")
            candidate = target.execute(plan)
            steps.append(f"{plan.operation.value}_CANDIDATE_CREATED")
            identity_status = (
                RecoveryStatus.PASS
                if canonical_sha256(candidate) == canonical_sha256(plan.expected_target)
                else RecoveryStatus.FAIL
            )
            if identity_status is not RecoveryStatus.PASS:
                reason = "CANDIDATE_IDENTITY_MISMATCH"
            elif clock.cancelled():
                reason = "CANCELLED_AFTER_RECOVERY"
            elif clock.monotonic() - started > policy.execution.rehearsal_deadline_seconds:
                reason = "LOCAL_DEADLINE_EXCEEDED"
            else:
                verifications = verifier.verify(plan, candidate)
                native_status = _status_for_verifications(verifications)
                steps.append("NATIVE_VERIFICATION_COMPLETED")
                reason = (
                    "LOCAL_RECOVERY_VERIFIED"
                    if native_status is RecoveryStatus.PASS
                    else "NATIVE_VERIFICATION_INCOMPLETE"
                )
    except PermissionError:
        authorization_status = RecoveryStatus.FAIL
        reason = "RECOVERY_AUTHORIZATION_DENIED"
    except Exception:
        if identity_status is RecoveryStatus.NOT_RUN:
            identity_status = RecoveryStatus.INDETERMINATE
        reason = "RECOVERY_EXECUTION_INDETERMINATE"
    finally:
        if _count(target.execute_count) or not target.is_clean():
            try:
                target.cleanup()
            except Exception:
                reason = "RECOVERY_CLEANUP_FAILED"
            else:
                steps.append("ISOLATED_CANDIDATE_CLEANED")

    completed_at = clock.now_utc()
    elapsed = max(0, int(clock.monotonic() - started))
    cleanup_status = RecoveryStatus.PASS if target.is_clean() else RecoveryStatus.FAIL
    rpo_status = (
        RecoveryStatus.PASS if age <= policy.objectives.target_rpo_seconds else RecoveryStatus.FAIL
    )
    rto_status = (
        RecoveryStatus.PASS
        if elapsed <= policy.objectives.target_rto_seconds
        else RecoveryStatus.FAIL
    )
    gates = (
        rpo_status,
        rto_status,
        identity_status,
        authorization_status,
        native_status,
        cleanup_status,
    )
    local_status = (
        RecoveryStatus.PASS
        if all(item is RecoveryStatus.PASS for item in gates)
        else RecoveryStatus.FAIL
        if any(item is RecoveryStatus.FAIL for item in gates)
        else RecoveryStatus.INDETERMINATE
    )
    return RecoveryEvidence(
        operation_id=plan.operation_id,
        plan_identity_sha256=plan_identity,
        source_identity_sha256=plan.source.artifact_identity_sha256,
        candidate_identity_sha256=candidate.artifact_identity_sha256,
        recovery_point_age_seconds=age,
        elapsed_seconds=elapsed,
        rpo_status=rpo_status,
        rto_status=rto_status,
        identity_status=identity_status,
        authorization_status=authorization_status,
        native_status=native_status,
        cleanup_status=cleanup_status,
        local_contract_status=local_status,
        verifications=verifications,
        executed_steps=tuple(steps),
        safe_reason_code=reason,
        started_at=started_at,
        completed_at=completed_at,
    )
