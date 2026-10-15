"""Strict immutable W9-003 model-package, approval, and audit contracts."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_ai_platform.experiment_tracking.models import ExperimentRun, RunStatus
from enterprise_ai_platform.retrieval.models import Classification
from enterprise_ai_platform.training.models import (
    TrainingCodeIdentity,
    TrainingContainerIdentity,
    TrainingOutcome,
    TrainingResult,
)

from .serialization import fingerprint

SHA256_PATTERN = r"^[0-9a-f]{64}$"
UUID_PATTERN = r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
SAFE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
SAFE_REASON_PATTERN = r"^[A-Z][A-Z0-9_]{0,79}$"


class RegistryModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class ApprovalState(StrEnum):
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


class PromotionStage(StrEnum):
    CANDIDATE = "CANDIDATE"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"


class ApprovalDecision(StrEnum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AuditAction(StrEnum):
    REGISTERED = "REGISTERED"
    REVIEWED = "REVIEWED"
    PROMOTED = "PROMOTED"
    KNOWN_GOOD_RECORDED = "KNOWN_GOOD_RECORDED"
    PROMOTION_CANCELLED = "PROMOTION_CANCELLED"
    ROLLED_BACK = "ROLLED_BACK"
    DELETED = "DELETED"


def _utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError(f"{label} must use UTC")
    return value.astimezone(UTC)


class ModelArtifactIdentity(RegistryModel):
    source_uri: str = Field(min_length=1, max_length=2000)
    object_version_id: str = Field(min_length=1, max_length=256)
    sha256: str = Field(pattern=SHA256_PATTERN)
    size_bytes: int = Field(gt=0, le=1_099_511_627_776)
    region: Literal["ap-southeast-1"] = "ap-southeast-1"

    @field_validator("source_uri")
    @classmethod
    def require_versioned_safe_s3_uri(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "s3"
            or not parsed.netloc
            or parsed.path in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.username
            or parsed.password
        ):
            raise ValueError("model artifact must use a credential-free S3 object URI")
        if any(token in value.casefold() for token in ("password", "secret", "credential")):
            raise ValueError("model artifact URI contains credential-like material")
        return value


class ModelCard(RegistryModel):
    schema_version: Literal["w9-003.model-card.v1"] = "w9-003.model-card.v1"
    model_name: str = Field(pattern=SAFE_NAME_PATTERN)
    model_version: str = Field(pattern=SAFE_NAME_PATTERN)
    intended_uses: tuple[str, ...] = Field(min_length=1, max_length=16)
    limitations: tuple[str, ...] = Field(min_length=1, max_length=16)
    prohibited_uses: tuple[str, ...] = Field(min_length=1, max_length=16)
    training_data_provenance_sha256: str = Field(pattern=SHA256_PATTERN)
    evaluation_report_sha256: str = Field(pattern=SHA256_PATTERN)
    owner_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    license: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,79}$")

    @field_validator("model_version")
    @classmethod
    def reject_mutable_model_versions(cls, value: str) -> str:
        if value.casefold() in {"latest", "main", "master"}:
            raise ValueError("model version must be immutable")
        return value

    @model_validator(mode="after")
    def require_ordered_safe_statements(self) -> ModelCard:
        for values in (self.intended_uses, self.limitations, self.prohibited_uses):
            if values != tuple(sorted(set(values))):
                raise ValueError("model-card statements must be sorted and unique")
            if any(not value or len(value) > 200 for value in values):
                raise ValueError("model-card statements must be bounded")
        return self


class ModelPackageManifest(RegistryModel):
    schema_version: Literal["w9-003.model-package.v1"] = "w9-003.model-package.v1"
    package_id: str = Field(pattern=UUID_PATTERN)
    correlation_id: str = Field(pattern=UUID_PATTERN)
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    registrant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Classification
    artifact: ModelArtifactIdentity
    code: TrainingCodeIdentity
    container: TrainingContainerIdentity
    training_request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    training_result: TrainingResult
    experiment_run_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    experiment_run: ExperimentRun
    lineage_export_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    model_card: ModelCard
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_at: datetime
    deadline_at: datetime

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "package timestamps")

    @model_validator(mode="after")
    def require_exact_candidate_lineage(self) -> ModelPackageManifest:
        if self.classification not in {Classification.PUBLIC, Classification.INTERNAL}:
            raise ValueError("local registry accepts only PUBLIC or INTERNAL packages")
        if self.deadline_at <= self.requested_at:
            raise ValueError("package deadline must follow request time")
        if (self.deadline_at - self.requested_at).total_seconds() > 900:
            raise ValueError("package deadline exceeds nine hundred seconds")
        if self.training_result.outcome is not TrainingOutcome.CANDIDATE_READY:
            raise ValueError("registry admission requires a candidate-ready training result")
        if self.training_result.request_identity_sha256 != self.training_request_identity_sha256:
            raise ValueError("training request identity differs")
        if self.training_result.candidate_artifact_sha256 != self.artifact.sha256:
            raise ValueError("training result and model artifact identities differ")
        if self.experiment_run.status is not RunStatus.COMPLETED:
            raise ValueError("registry admission requires a completed experiment run")
        if fingerprint(self.experiment_run) != self.experiment_run_identity_sha256:
            raise ValueError("experiment run identity differs")
        envelope = self.experiment_run.envelope
        experiment = self.experiment_run.experiment_input
        if envelope.tenant_reference_sha256 != self.tenant_reference_sha256:
            raise ValueError("experiment and registry tenants differ")
        if envelope.classification != self.classification:
            raise ValueError("experiment and registry classifications differ")
        if experiment.code.git_commit != self.code.git_commit:
            raise ValueError("experiment and training code commits differ")
        if experiment.code.source_composition_sha256 != self.code.source_sha256:
            raise ValueError("experiment and training source compositions differ")
        if experiment.model.artifact_sha256 != self.artifact.sha256:
            raise ValueError("experiment and registry artifact identities differ")
        if experiment.model.license != self.model_card.license:
            raise ValueError("experiment and model-card licenses differ")
        if experiment.evaluation.gate_status != "PASS":
            raise ValueError("evaluation absolute gate must pass")
        if experiment.evaluation.baseline_comparison_status != "PASS":
            raise ValueError("evaluation baseline comparison must pass")
        if self.model_card.training_data_provenance_sha256 != experiment.dataset.manifest_sha256:
            raise ValueError("model-card training-data provenance differs")
        report_hashes = {
            artifact.sha256
            for artifact in experiment.artifacts
            if artifact.kind == "evaluation_report"
        }
        if self.model_card.evaluation_report_sha256 not in report_hashes:
            raise ValueError("model-card evaluation report is not in experiment lineage")
        return self


class RegistryRecord(RegistryModel):
    schema_version: Literal["w9-003.registry-record.v1"] = "w9-003.registry-record.v1"
    package: ModelPackageManifest
    package_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    approval_state: ApprovalState = ApprovalState.PENDING_REVIEW
    latest_approval_identity_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    retired_at: datetime | None = None

    @field_validator("retired_at")
    @classmethod
    def require_optional_utc(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _utc(value, "retirement timestamp")

    @model_validator(mode="after")
    def require_record_identity(self) -> RegistryRecord:
        if self.package_identity_sha256 != fingerprint(self.package):
            raise ValueError("registry record package identity differs")
        if self.approval_state is ApprovalState.SUPERSEDED and self.retired_at is None:
            raise ValueError("superseded records require a retirement timestamp")
        if self.approval_state is not ApprovalState.SUPERSEDED and self.retired_at is not None:
            raise ValueError("only superseded records may have a retirement timestamp")
        return self


class PackageApproval(RegistryModel):
    schema_version: Literal["w9-003.package-approval.v1"] = "w9-003.package-approval.v1"
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    package_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    requester_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_role: Literal["reviewer"] = "reviewer"
    decision: ApprovalDecision
    decided_at: datetime
    expires_at: datetime

    @field_validator("decided_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "approval timestamp")

    @model_validator(mode="after")
    def require_separation_and_expiry(self) -> PackageApproval:
        if self.requester_reference_sha256 == self.approver_reference_sha256:
            raise ValueError("registrant cannot approve their own package")
        if self.expires_at <= self.decided_at:
            raise ValueError("approval expiry must follow its decision")
        return self


class PromotionRequest(RegistryModel):
    schema_version: Literal["w9-003.promotion-request.v1"] = "w9-003.promotion-request.v1"
    request_id: str = Field(pattern=UUID_PATTERN)
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    executor_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    package_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    package_approval_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    source_stage: PromotionStage
    target_stage: PromotionStage
    expected_target_package_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_at: datetime
    deadline_at: datetime

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "promotion timestamp")

    @model_validator(mode="after")
    def require_adjacent_stage(self) -> PromotionRequest:
        if (self.source_stage, self.target_stage) not in {
            (PromotionStage.CANDIDATE, PromotionStage.STAGING),
            (PromotionStage.STAGING, PromotionStage.PRODUCTION),
        }:
            raise ValueError("promotion must advance exactly one approved stage")
        if self.deadline_at <= self.requested_at:
            raise ValueError("promotion deadline must follow request time")
        if (self.deadline_at - self.requested_at).total_seconds() > 900:
            raise ValueError("promotion deadline exceeds nine hundred seconds")
        return self


class PromotionApproval(RegistryModel):
    schema_version: Literal["w9-003.promotion-approval.v1"] = "w9-003.promotion-approval.v1"
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    promotion_request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    package_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    target_stage: PromotionStage
    requester_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_role: Literal["reviewer"] = "reviewer"
    decision: Literal["APPROVED"] = "APPROVED"
    decided_at: datetime
    expires_at: datetime

    @field_validator("decided_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "promotion approval timestamp")

    @model_validator(mode="after")
    def require_separation_and_expiry(self) -> PromotionApproval:
        if self.requester_reference_sha256 == self.approver_reference_sha256:
            raise ValueError("promotion executor cannot approve their own request")
        if self.expires_at <= self.decided_at:
            raise ValueError("promotion approval expiry must follow its decision")
        return self


class PromotionResult(RegistryModel):
    schema_version: Literal["w9-003.promotion-result.v1"] = "w9-003.promotion-result.v1"
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    package_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    target_stage: PromotionStage
    prior_target_package_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    generation: int = Field(ge=1)
    audit_event_sha256: str = Field(pattern=SHA256_PATTERN)
    status: Literal["PROMOTED"] = "PROMOTED"
    deployment_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"


class KnownGoodReference(RegistryModel):
    schema_version: Literal["w9-003.known-good-reference.v1"] = "w9-003.known-good-reference.v1"
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    stage: PromotionStage
    package_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    promotion_event_sha256: str = Field(pattern=SHA256_PATTERN)
    reviewer_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    marked_at: datetime

    @field_validator("marked_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "known-good timestamp")

    @model_validator(mode="after")
    def reject_candidate_stage(self) -> KnownGoodReference:
        if self.stage is PromotionStage.CANDIDATE:
            raise ValueError("candidate stage cannot be marked known-good")
        return self


class RollbackRequest(RegistryModel):
    schema_version: Literal["w9-003.rollback-request.v1"] = "w9-003.rollback-request.v1"
    request_id: str = Field(pattern=UUID_PATTERN)
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    executor_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    stage: PromotionStage
    expected_current_package_sha256: str = Field(pattern=SHA256_PATTERN)
    known_good_package_sha256: str = Field(pattern=SHA256_PATTERN)
    known_good_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_at: datetime
    deadline_at: datetime

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "rollback timestamp")

    @model_validator(mode="after")
    def require_distinct_bounded_rollback(self) -> RollbackRequest:
        if self.stage is PromotionStage.CANDIDATE:
            raise ValueError("candidate stage cannot be rolled back")
        if self.expected_current_package_sha256 == self.known_good_package_sha256:
            raise ValueError("rollback target must differ from current package")
        if self.deadline_at <= self.requested_at:
            raise ValueError("rollback deadline must follow request time")
        if (self.deadline_at - self.requested_at).total_seconds() > 900:
            raise ValueError("rollback deadline exceeds nine hundred seconds")
        return self


class RollbackApproval(RegistryModel):
    schema_version: Literal["w9-003.rollback-approval.v1"] = "w9-003.rollback-approval.v1"
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    rollback_request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    current_package_sha256: str = Field(pattern=SHA256_PATTERN)
    known_good_package_sha256: str = Field(pattern=SHA256_PATTERN)
    requester_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_role: Literal["reviewer"] = "reviewer"
    decision: Literal["APPROVED"] = "APPROVED"
    decided_at: datetime
    expires_at: datetime

    @field_validator("decided_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "rollback approval timestamp")

    @model_validator(mode="after")
    def require_separation_and_expiry(self) -> RollbackApproval:
        if self.requester_reference_sha256 == self.approver_reference_sha256:
            raise ValueError("rollback executor cannot approve their own request")
        if self.expires_at <= self.decided_at:
            raise ValueError("rollback approval expiry must follow its decision")
        return self


class RollbackResult(RegistryModel):
    schema_version: Literal["w9-003.rollback-result.v1"] = "w9-003.rollback-result.v1"
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    failed_package_sha256: str = Field(pattern=SHA256_PATTERN)
    restored_package_sha256: str = Field(pattern=SHA256_PATTERN)
    stage: PromotionStage
    generation: int = Field(ge=1)
    audit_event_sha256: str = Field(pattern=SHA256_PATTERN)
    status: Literal["RESTORED_KNOWN_GOOD"] = "RESTORED_KNOWN_GOOD"
    failed_candidate_preserved: Literal[True] = True
    deployment_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"


class AuditEvent(RegistryModel):
    schema_version: Literal["w9-003.audit-event.v1"] = "w9-003.audit-event.v1"
    sequence: int = Field(ge=1, le=1000)
    previous_event_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    action: AuditAction
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    actor_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    package_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    detail_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    occurred_at: datetime

    @field_validator("occurred_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "audit timestamp")


class AuditRecord(RegistryModel):
    event: AuditEvent
    event_identity_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_event_identity(self) -> AuditRecord:
        if self.event_identity_sha256 != fingerprint(self.event):
            raise ValueError("audit event identity differs")
        return self


class AuditExport(RegistryModel):
    schema_version: Literal["w9-003.audit-export.v1"] = "w9-003.audit-export.v1"
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    exported_at: datetime
    records: tuple[AuditRecord, ...] = Field(max_length=1000)

    @field_validator("exported_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _utc(value, "audit export timestamp")

    @model_validator(mode="after")
    def require_complete_hash_chain(self) -> AuditExport:
        for index, record in enumerate(self.records):
            if record.event.sequence != index + 1:
                raise ValueError("audit sequence is not contiguous")
            expected = None if index == 0 else self.records[index - 1].event_identity_sha256
            if record.event.previous_event_sha256 != expected:
                raise ValueError("audit hash chain differs")
        return self


class CleanupPlan(RegistryModel):
    schema_version: Literal["w9-003.cleanup-plan.v1"] = "w9-003.cleanup-plan.v1"
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    exact_package_ids: tuple[str, ...] = Field(max_length=100)
    audit_export_identity_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    retain_failed_candidates: Literal[True] = True
    retain_audit_evidence: Literal[True] = True
    retention_days: Literal[180] = 180
    delete_shared_resources: Literal[False] = False
    owner_approval_required: Literal[True] = True
    status: Literal["NOT_RUN"] = "NOT_RUN"

    @field_validator("exact_package_ids")
    @classmethod
    def require_sorted_unique_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(set(values))):
            raise ValueError("cleanup package IDs must be sorted and unique")
        return values
