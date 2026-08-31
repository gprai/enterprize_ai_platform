"""Strict, content-free models for the bounded W4-002 agent controller."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Final, Literal
from uuid import UUID

from pydantic import UUID4, BaseModel, ConfigDict, Field, field_validator, model_validator

AGENT_STATE_SCHEMA_VERSION: Final[Literal["w4-002.agent-state.v1"]] = "w4-002.agent-state.v1"
AGENT_GRAPH_VERSION: Final[Literal["w4-002.graph.v1"]] = "w4-002.graph.v1"
AGENT_STORE_SCHEMA_VERSION: Final[Literal["w4-002.agent-store.v1"]] = "w4-002.agent-store.v1"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class AgentModel(BaseModel):
    """Immutable strict base for every durable agent control value."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class AgentNode(StrEnum):
    VALIDATE_INPUT = "validate_input"
    AUTHORIZE = "authorize"
    RETRIEVE = "retrieve"
    GRADE_EVIDENCE = "grade_evidence"
    ANSWER = "answer"
    PROPOSE_TOOL = "propose_tool"
    AWAIT_HUMAN_APPROVAL = "await_human_approval"
    EXECUTE_TOOL = "execute_tool"
    SAFE_TERMINAL = "safe_terminal"


class AgentOutcome(StrEnum):
    COMPLETED = "completed"
    APPROVAL_REQUIRED = "approval_required"
    DENIED = "denied"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    BUDGET_EXCEEDED = "budget_exceeded"
    TIMED_OUT = "timed_out"
    SAFE_TERMINAL = "safe_terminal"


class TerminalReason(StrEnum):
    ANSWER_REFERENCE_READY = "answer_reference_ready"
    READ_TOOL_COMPLETED = "read_tool_completed"
    APPROVAL_REQUIRED = "approval_required"
    WRITE_TOOL_COMPLETED = "write_tool_completed"
    AUTHORIZATION_DENIED = "authorization_denied"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_CANCELLED = "approval_cancelled"
    APPROVAL_CONFLICT = "approval_conflict"
    STEP_BUDGET_EXCEEDED = "step_budget_exceeded"
    TOOL_BUDGET_EXCEEDED = "tool_budget_exceeded"
    PROVIDER_BUDGET_EXCEEDED = "provider_budget_exceeded"
    # Stable terminal-reason code, not a credential.
    TOKEN_BUDGET_EXCEEDED = "token_budget_exceeded"  # noqa: S105
    STATE_BUDGET_EXCEEDED = "state_budget_exceeded"
    DEADLINE_EXCEEDED = "deadline_exceeded"
    EVIDENCE_NOT_AUTHORIZED = "evidence_not_authorized"
    EVIDENCE_INSUFFICIENT = "evidence_insufficient"
    SAFE_FAILURE = "safe_failure"


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    EXECUTING = "executing"
    CONSUMED = "consumed"
    EXECUTION_UNKNOWN = "execution_unknown"


class ToolKind(StrEnum):
    READ = "read"
    MOCK_WRITE = "mock_write"


class AgentBudgets(AgentModel):
    maximum_graph_steps: int = Field(default=8, ge=1, le=8)
    maximum_tool_calls: int = Field(default=1, ge=1, le=1)
    maximum_provider_attempts: int = Field(default=1, ge=1, le=1)
    maximum_total_tokens: int = Field(default=4096, ge=1, le=4096)
    graph_retries: Literal[0] = 0
    agent_deadline_seconds: int = Field(default=25, ge=1, le=25)
    maximum_serialized_state_bytes: int = Field(default=16_384, ge=1, le=16_384)
    maximum_concurrent_agent_runs: Literal[1] = 1
    agent_queue_capacity: Literal[0] = 0


class AuditDecision(AgentModel):
    sequence: int = Field(ge=1, le=8)
    node: AgentNode
    decision: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)


class ServiceStatusArguments(AgentModel):
    component: Literal["query_wiring"]


class MockSetServiceModeArguments(AgentModel):
    mode: Literal["maintenance"]


ToolArguments = ServiceStatusArguments | MockSetServiceModeArguments


class ToolProposal(AgentModel):
    name: Literal["get_service_status", "mock_set_service_mode"]
    version: Literal["1.0"] = "1.0"
    kind: ToolKind
    arguments: ToolArguments

    @model_validator(mode="after")
    def validate_tool_arguments(self) -> ToolProposal:
        if self.name == "get_service_status" and not isinstance(
            self.arguments,
            ServiceStatusArguments,
        ):
            raise ValueError("read tool requires query-wiring arguments")
        if self.name == "mock_set_service_mode" and not isinstance(
            self.arguments,
            MockSetServiceModeArguments,
        ):
            raise ValueError("mock write tool requires maintenance arguments")
        if self.name == "get_service_status" and self.kind is not ToolKind.READ:
            raise ValueError("read tool kind is invalid")
        if self.name == "mock_set_service_mode" and self.kind is not ToolKind.MOCK_WRITE:
            raise ValueError("mock write tool kind is invalid")
        return self


class EvidencePacket(AgentModel):
    references: tuple[str, ...] = Field(default=(), max_length=5)

    @field_validator("references")
    @classmethod
    def validate_references(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if len(values) != len(set(values)):
            raise ValueError("evidence references must be unique")
        if any(
            len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
            for value in values
        ):
            raise ValueError("evidence references must be lowercase SHA-256 values")
        return values


class EvidenceGrade(AgentModel):
    authorized: bool
    sufficient: bool


class AnswerReference(AgentModel):
    result_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    total_tokens: int = Field(ge=0, le=4096)


class ApprovalRecord(AgentModel):
    schema_version: Literal["w4-002.agent-store.v1"] = AGENT_STORE_SCHEMA_VERSION
    revision: int = Field(default=1, ge=1)
    approval_id: UUID4
    request_id: UUID4
    run_id: UUID4
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    requester_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    approver_role: Literal["reviewer"] | None = None
    tool_name: Literal["mock_set_service_mode"]
    tool_version: Literal["1.0"] = "1.0"
    arguments_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    decision: Literal["approved"] | None = None
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: datetime
    decided_at: datetime | None = None
    expires_at: datetime
    terminal_at: datetime | None = None
    result_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    safe_error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9_]+$",
    )

    @field_validator("created_at", "decided_at", "expires_at", "terminal_at")
    @classmethod
    def normalize_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> ApprovalRecord:
        if self.expires_at <= self.created_at:
            raise ValueError("approval expiry must follow creation")
        if self.status is ApprovalStatus.PENDING:
            if any(
                value is not None
                for value in (
                    self.approver_reference_sha256,
                    self.approver_role,
                    self.idempotency_key_sha256,
                    self.decision,
                    self.decided_at,
                    self.terminal_at,
                    self.result_reference_sha256,
                    self.safe_error_code,
                )
            ):
                raise ValueError("pending approval contains decision fields")
        elif self.status in {
            ApprovalStatus.APPROVED,
            ApprovalStatus.EXECUTING,
            ApprovalStatus.CONSUMED,
            ApprovalStatus.EXECUTION_UNKNOWN,
        }:
            if any(
                value is None
                for value in (
                    self.approver_reference_sha256,
                    self.approver_role,
                    self.idempotency_key_sha256,
                    self.decision,
                    self.decided_at,
                )
            ):
                raise ValueError("executing approval is missing decision bindings")
        if (
            self.status
            in {
                ApprovalStatus.REJECTED,
                ApprovalStatus.EXPIRED,
                ApprovalStatus.CANCELLED,
                ApprovalStatus.CONSUMED,
                ApprovalStatus.EXECUTION_UNKNOWN,
            }
            and self.terminal_at is None
        ):
            raise ValueError("terminal approval is missing its terminal timestamp")
        if self.status is ApprovalStatus.CONSUMED and self.result_reference_sha256 is None:
            raise ValueError("consumed approval is missing its result reference")
        if self.status is ApprovalStatus.EXECUTION_UNKNOWN and self.safe_error_code is None:
            raise ValueError("uncertain execution is missing its safe error code")
        return self


class AgentState(AgentModel):
    schema_version: Literal["w4-002.agent-state.v1"] = AGENT_STATE_SCHEMA_VERSION
    graph_version: Literal["w4-002.graph.v1"] = AGENT_GRAPH_VERSION
    revision: int = Field(default=1, ge=1)
    request_id: UUID4
    run_id: UUID4
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    subject_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    current_node: AgentNode
    step_count: int = Field(default=0, ge=0, le=8)
    outcome: AgentOutcome | None = None
    terminal_reason: TerminalReason | None = None
    evidence_reference_sha256: tuple[str, ...] = Field(default=(), max_length=5)
    tool_name: Literal["get_service_status", "mock_set_service_mode"] | None = None
    tool_version: Literal["1.0"] | None = None
    arguments_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    approval_id: UUID4 | None = None
    approval_status: ApprovalStatus | None = None
    approval_expires_at: datetime | None = None
    tool_call_count: int = Field(default=0, ge=0, le=1)
    provider_attempt_count: int = Field(default=0, ge=0, le=1)
    retry_count: Literal[0] = 0
    total_tokens: int = Field(default=0, ge=0, le=4096)
    elapsed_milliseconds: int = Field(default=0, ge=0, le=25_000)
    idempotency_key_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    audit_decisions: tuple[AuditDecision, ...] = Field(default=(), max_length=8)
    result_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    safe_error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9_]+$",
    )

    @field_validator("approval_expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval expiry must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_terminal_state(self) -> AgentState:
        if (self.outcome is None) != (self.terminal_reason is None):
            raise ValueError("outcome and terminal reason must be set together")
        if self.tool_name is None and any(
            value is not None for value in (self.tool_version, self.arguments_sha256)
        ):
            raise ValueError("tool bindings require a tool name")
        if len(self.evidence_reference_sha256) != len(set(self.evidence_reference_sha256)):
            raise ValueError("evidence references must be unique")
        return self


class AgentResult(AgentModel):
    request_id: UUID4
    run_id: UUID4
    outcome: AgentOutcome
    terminal_reason: TerminalReason
    approval_id: UUID4 | None = None
    result_reference_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    safe_error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9_]+$",
    )


class StartAgentCommand(AgentModel):
    action: Literal["start"] = "start"
    query: str = Field(min_length=1, max_length=10_000)


class DecideAgentCommand(AgentModel):
    action: Literal["decide"] = "decide"
    approval_id: UUID4
    idempotency_key: UUID
    decision: Literal["approved"] = "approved"
    tool_name: Literal["mock_set_service_mode"]
    tool_version: Literal["1.0"]
    arguments: MockSetServiceModeArguments


AgentCommand = StartAgentCommand | DecideAgentCommand
