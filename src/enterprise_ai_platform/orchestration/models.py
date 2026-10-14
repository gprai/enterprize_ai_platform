"""Strict identities, states, and outcomes for W8-003 orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import UUID4, BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import Classification
from enterprise_ai_platform.serving.models import ArtifactIdentity, ServingProvider

SHA256_PATTERN = r"^[0-9a-f]{64}$"
SAFE_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{0,79}$"
MAXIMUM_ATTEMPTS = 3
MAXIMUM_FANOUT = 8
MAXIMUM_TRANSITIONS = 32


class OrchestrationModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
        populate_by_name=True,
    )


class WorkflowKind(StrEnum):
    ASYNCHRONOUS_INFERENCE = "asynchronous_inference"
    LONG_RUNNING_INGESTION = "long_running_ingestion"
    MODEL_TRAINING = "model_training"


class WorkflowState(StrEnum):
    RECEIVED = "RECEIVED"
    AUTHORIZED = "AUTHORIZED"
    IDEMPOTENCY_RESERVED = "IDEMPOTENCY_RESERVED"
    QUOTA_RESERVED = "QUOTA_RESERVED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    READY = "READY"
    RUNNING = "RUNNING"
    RETRY_WAIT = "RETRY_WAIT"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    COMPENSATING = "COMPENSATING"
    SUCCEEDED = "SUCCEEDED"
    DENIED = "DENIED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    COMPENSATED = "COMPENSATED"
    DEAD_LETTERED = "DEAD_LETTERED"


TERMINAL_STATES = frozenset(
    {
        WorkflowState.SUCCEEDED,
        WorkflowState.DENIED,
        WorkflowState.TIMED_OUT,
        WorkflowState.CANCELLED,
        WorkflowState.COMPENSATED,
        WorkflowState.DEAD_LETTERED,
    }
)


class FailureClass(StrEnum):
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    TENANT_QUOTA_EXCEEDED = "TENANT_QUOTA_EXCEEDED"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    VALIDATION_REJECTED = "VALIDATION_REJECTED"
    UNSUPPORTED_CLASSIFICATION = "UNSUPPORTED_CLASSIFICATION"
    APPROVAL_DENIED = "APPROVAL_DENIED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    UNAPPROVED_MODEL = "UNAPPROVED_MODEL"
    UNAPPROVED_PROVIDER = "UNAPPROVED_PROVIDER"
    TRANSIENT_DEPENDENCY = "TRANSIENT_DEPENDENCY"
    PERMANENT_DEPENDENCY = "PERMANENT_DEPENDENCY"
    DEPENDENCY_OUTCOME_UNKNOWN = "DEPENDENCY_OUTCOME_UNKNOWN"
    TASK_TIMEOUT = "TASK_TIMEOUT"
    WORKFLOW_TIMEOUT = "WORKFLOW_TIMEOUT"
    CANCELLED = "CANCELLED"
    RETRY_EXHAUSTED = "RETRY_EXHAUSTED"
    COMPENSATION_REQUIRED = "COMPENSATION_REQUIRED"
    COMPENSATION_FAILED = "COMPENSATION_FAILED"
    DEAD_LETTER_UNAVAILABLE = "DEAD_LETTER_UNAVAILABLE"
    STATE_CONFLICT = "STATE_CONFLICT"


class ApprovalRequirement(StrEnum):
    NONE = "none"
    SENSITIVE = "sensitive"
    HIGH_COST = "high_cost"
    TRAINING = "training"


class ApprovalStatus(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class CostClass(StrEnum):
    LOW = "low"
    STANDARD = "standard"
    HIGH = "high"


class TaskDisposition(StrEnum):
    SUCCESS = "success"
    RETRYABLE_FAILURE = "retryable_failure"
    PERMANENT_FAILURE = "permanent_failure"
    PARTIAL_EFFECT = "partial_effect"
    OUTCOME_UNKNOWN = "outcome_unknown"


class ResumeAction(StrEnum):
    RETRY = "retry"
    COMPENSATE = "compensate"
    DEAD_LETTER = "dead_letter"


class WorkflowRequest(OrchestrationModel):
    schema_version: Literal["w8-003.workflow-request.v1"] = "w8-003.workflow-request.v1"
    workflow_id: UUID4
    workflow_kind: WorkflowKind
    correlation_id: UUID4
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    subject_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Classification
    input_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact: ArtifactIdentity | None = None
    requested_provider: ServingProvider | None = None
    training_request_identity_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    approval_requirement: ApprovalRequirement = ApprovalRequirement.NONE
    cost_class: CostClass = CostClass.STANDARD
    cost_estimate_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    requested_at: datetime
    deadline_at: datetime

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("workflow timestamps must be UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_consistent_admission(self) -> WorkflowRequest:
        if self.deadline_at <= self.requested_at:
            raise ValueError("workflow deadline must follow request time")
        if self.workflow_kind is WorkflowKind.ASYNCHRONOUS_INFERENCE and self.artifact is None:
            raise ValueError("inference workflows require an approved artifact identity")
        if self.workflow_kind is WorkflowKind.MODEL_TRAINING and (
            self.artifact is not None
            or self.requested_provider is not None
            or self.training_request_identity_sha256 is None
        ):
            raise ValueError("training requires its own request identity without a serving route")
        if self.workflow_kind is WorkflowKind.LONG_RUNNING_INGESTION and (
            self.artifact is not None
            or self.requested_provider is not None
            or self.training_request_identity_sha256 is not None
        ):
            raise ValueError("ingestion cannot select a model provider")
        if self.workflow_kind is not WorkflowKind.MODEL_TRAINING and (
            self.training_request_identity_sha256 is not None
        ):
            raise ValueError("only training workflows may contain a training request identity")
        if self.requested_provider is not None and self.artifact is None:
            raise ValueError("provider selection requires an artifact identity")
        sensitive = self.classification in {
            Classification.CONFIDENTIAL,
            Classification.RESTRICTED,
        }
        if sensitive and self.approval_requirement is ApprovalRequirement.NONE:
            raise ValueError("sensitive workflows require approval")
        if self.workflow_kind is WorkflowKind.MODEL_TRAINING and (
            self.approval_requirement is not ApprovalRequirement.TRAINING
        ):
            raise ValueError("training workflows require training approval")
        if self.cost_class is CostClass.HIGH and (
            self.approval_requirement is ApprovalRequirement.NONE
            or self.cost_estimate_reference_sha256 is None
        ):
            raise ValueError("high-cost workflows require approval and a cost identity")
        if self.workflow_kind is WorkflowKind.MODEL_TRAINING and (
            self.cost_estimate_reference_sha256 is None
        ):
            raise ValueError("training workflows require a cost identity")
        if (
            self.workflow_kind is WorkflowKind.LONG_RUNNING_INGESTION
            and self.classification not in {Classification.PUBLIC, Classification.INTERNAL}
        ):
            raise ValueError("existing governed ingestion supports PUBLIC and INTERNAL only")
        return self


class EventBridgeEnvelope(OrchestrationModel):
    version: Literal["0"] = "0"
    id: UUID4
    detail_type: Literal[
        "AsynchronousInferenceRequested",
        "LongRunningIngestionRequested",
        "ModelTrainingRequested",
    ] = Field(alias="detail-type")
    source: Literal["enterprise_ai_platform.orchestration"] = "enterprise_ai_platform.orchestration"
    account: str = Field(pattern=r"^[0-9]{12}$")
    time: datetime
    region: Literal["ap-southeast-1"] = "ap-southeast-1"
    resources: tuple[str, ...] = Field(default=(), max_length=8)
    detail: WorkflowRequest

    @field_validator("time")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("event time must be UTC")
        return value.astimezone(UTC)

    @field_validator("resources")
    @classmethod
    def require_unique_resources(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)) or any(not value for value in values):
            raise ValueError("event resources must be non-empty and unique")
        return values

    @model_validator(mode="after")
    def require_matching_event_kind(self) -> EventBridgeEnvelope:
        expected = {
            WorkflowKind.ASYNCHRONOUS_INFERENCE: "AsynchronousInferenceRequested",
            WorkflowKind.LONG_RUNNING_INGESTION: "LongRunningIngestionRequested",
            WorkflowKind.MODEL_TRAINING: "ModelTrainingRequested",
        }[self.detail.workflow_kind]
        if self.detail_type != expected:
            raise ValueError("event detail type differs from workflow kind")
        if self.time != self.detail.requested_at:
            raise ValueError("event and workflow request timestamps differ")
        return self


class WorkflowExecutionState(OrchestrationModel):
    schema_version: Literal["w8-003.workflow-state.v1"] = "w8-003.workflow-state.v1"
    revision: int = Field(ge=1)
    event_id: UUID4
    workflow_id: UUID4
    workflow_kind: WorkflowKind
    state: WorkflowState
    correlation_id: UUID4
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    subject_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Classification
    input_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    artifact_identity_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    training_request_identity_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    provider: ServingProvider | None = None
    attempt_count: int = Field(default=0, ge=0, le=MAXIMUM_ATTEMPTS)
    transition_count: int = Field(default=1, ge=1, le=MAXIMUM_TRANSITIONS)
    fanout_count: int = Field(default=0, ge=0, le=MAXIMUM_FANOUT)
    task_timeout_seconds: int = Field(gt=0)
    deadline_at: datetime
    next_retry_at: datetime | None = None
    approval_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    approval_status: ApprovalStatus | None = None
    result_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    effect_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    resume_token_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    compensation_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    failure_class: FailureClass | None = None
    safe_reason_code: str = Field(pattern=SAFE_CODE_PATTERN)
    latest_transition_sha256: str = Field(pattern=SHA256_PATTERN)
    created_at: datetime
    updated_at: datetime
    completed_at: datetime | None = None

    @field_validator("deadline_at", "next_retry_at", "created_at", "updated_at", "completed_at")
    @classmethod
    def require_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("workflow state timestamps must be UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_state_consistency(self) -> WorkflowExecutionState:
        terminal = self.state in TERMINAL_STATES
        if terminal != (self.completed_at is not None):
            raise ValueError("terminal state and completion timestamp differ")
        if self.state is WorkflowState.SUCCEEDED and self.result_reference_sha256 is None:
            raise ValueError("successful workflow is missing its result identity")
        if self.state is WorkflowState.RETRY_WAIT and self.next_retry_at is None:
            raise ValueError("retry state is missing its retry timestamp")
        if self.state is not WorkflowState.RETRY_WAIT and self.next_retry_at is not None:
            raise ValueError("non-retry state contains a retry timestamp")
        if self.state is WorkflowState.RECONCILIATION_REQUIRED and (
            self.resume_token_sha256 is None
        ):
            raise ValueError("reconciliation state is missing its resume identity")
        if self.state is WorkflowState.SUCCEEDED and self.failure_class is not None:
            raise ValueError("successful workflow cannot contain a failure class")
        return self


class WorkflowTransition(OrchestrationModel):
    schema_version: Literal["w8-003.workflow-transition.v1"] = "w8-003.workflow-transition.v1"
    workflow_id: UUID4
    correlation_id: UUID4
    revision: int = Field(ge=1)
    previous_state: WorkflowState | None
    next_state: WorkflowState
    safe_reason_code: str = Field(pattern=SAFE_CODE_PATTERN)
    failure_class: FailureClass | None = None
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    prior_transition_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    transition_sha256: str = Field(pattern=SHA256_PATTERN)
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("transition timestamp must be UTC")
        return value.astimezone(UTC)


class ApprovalDecision(OrchestrationModel):
    schema_version: Literal["w8-003.approval-decision.v1"] = "w8-003.approval-decision.v1"
    status: ApprovalStatus
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    requester_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_role: Literal["reviewer"] = "reviewer"
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    decided_at: datetime
    expires_at: datetime

    @field_validator("decided_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("approval timestamps must be UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_independent_live_approval(self) -> ApprovalDecision:
        if self.approver_reference_sha256 == self.requester_reference_sha256:
            raise ValueError("requester cannot approve the same workflow")
        if self.expires_at <= self.decided_at:
            raise ValueError("approval expiry must follow its decision")
        return self


class TaskResult(OrchestrationModel):
    disposition: TaskDisposition
    attempts_consumed: int = Field(default=1, ge=1, le=MAXIMUM_ATTEMPTS)
    fanout_consumed: int = Field(default=0, ge=0, le=MAXIMUM_FANOUT)
    result_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    effect_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    failure_class: FailureClass | None = None
    safe_reason_code: str | None = Field(default=None, pattern=SAFE_CODE_PATTERN)

    @model_validator(mode="after")
    def require_disposition_fields(self) -> TaskResult:
        if self.disposition is TaskDisposition.SUCCESS:
            if self.result_reference_sha256 is None or any(
                value is not None
                for value in (
                    self.effect_reference_sha256,
                    self.failure_class,
                    self.safe_reason_code,
                )
            ):
                raise ValueError("successful task has inconsistent fields")
        elif self.disposition is TaskDisposition.PARTIAL_EFFECT:
            if self.effect_reference_sha256 is None or self.failure_class is None:
                raise ValueError("partial effect is missing its effect or failure identity")
        elif self.failure_class is None or self.safe_reason_code is None:
            raise ValueError("failed task is missing its safe classification")
        return self


class CompensationResult(OrchestrationModel):
    succeeded: bool
    compensation_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    safe_reason_code: str | None = Field(default=None, pattern=SAFE_CODE_PATTERN)

    @model_validator(mode="after")
    def require_result_fields(self) -> CompensationResult:
        if self.succeeded != (self.compensation_reference_sha256 is not None):
            raise ValueError("compensation status and identity differ")
        if not self.succeeded and self.safe_reason_code is None:
            raise ValueError("failed compensation requires a safe reason")
        return self


class ReservationStatus(StrEnum):
    NEW = "NEW"
    REPLAY = "REPLAY"
    CONFLICT = "CONFLICT"
    IN_PROGRESS = "IN_PROGRESS"


class IdempotencyReservation(OrchestrationModel):
    status: ReservationStatus
    prior_state: WorkflowExecutionState | None = None

    @model_validator(mode="after")
    def require_prior_state_for_replay(self) -> IdempotencyReservation:
        if (self.status is ReservationStatus.REPLAY) != (self.prior_state is not None):
            raise ValueError("idempotency replay and prior state differ")
        return self


class DeadLetterRecord(OrchestrationModel):
    schema_version: Literal["w8-003.dead-letter.v1"] = "w8-003.dead-letter.v1"
    workflow_id: UUID4
    correlation_id: UUID4
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    failure_class: FailureClass
    safe_reason_code: str = Field(pattern=SAFE_CODE_PATTERN)
    attempt_count: int = Field(ge=0, le=MAXIMUM_ATTEMPTS)
    state_revision: int = Field(ge=1)
    recorded_at: datetime

    @field_validator("recorded_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("dead-letter timestamp must be UTC")
        return value.astimezone(UTC)


class RetryPolicy(OrchestrationModel):
    maximum_attempts: Literal[3] = 3
    backoff_seconds: tuple[Literal[1], Literal[2]] = (1, 2)
    multiplier: float = Field(default=2.0, ge=2.0, le=2.0)
    jitter: Literal["none"] = "none"


class WorkflowTimeout(OrchestrationModel):
    task_seconds: int = Field(gt=0)
    workflow_seconds: int = Field(gt=0)

    @model_validator(mode="after")
    def require_task_below_workflow(self) -> WorkflowTimeout:
        if self.task_seconds >= self.workflow_seconds:
            raise ValueError("task timeout must be below workflow timeout")
        return self
