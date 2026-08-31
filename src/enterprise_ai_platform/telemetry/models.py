"""Strict, content-free telemetry schemas for W3-09 and W4-08."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Final, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

TELEMETRY_SCHEMA_VERSION: Final = "w4-003.telemetry.v1"
MAX_SERVICE_NAME_LENGTH: Final = 64
MAX_SAFE_CODE_LENGTH: Final = 100
SPAN_CAPACITY: Final = 512
LOG_CAPACITY: Final = 512


class TelemetryStage(StrEnum):
    API = "api"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    GUARDRAIL = "guardrail"
    RAG = "rag"
    RETRIEVAL = "retrieval"
    EMBEDDING = "embedding"
    VECTOR_SEARCH = "vector_search"
    LLM = "llm"
    AGENT = "agent"
    GRAPH = "graph"
    APPROVAL = "approval"
    TOOL = "tool"
    TELEMETRY = "telemetry"


class TelemetryOperation(StrEnum):
    REQUEST = "request"
    AUTHENTICATE = "authenticate"
    AUTHORIZE = "authorize"
    VALIDATE = "validate"
    ANSWER = "answer"
    RETRIEVE = "retrieve"
    EMBED_QUERY = "embed_query"
    EMBED_DOCUMENTS = "embed_documents"
    SEARCH = "search"
    CHAT = "chat"
    HANDLE = "handle"
    VALIDATE_INPUT = "validate_input"
    GRADE_EVIDENCE = "grade_evidence"
    PROPOSE_TOOL = "propose_tool"
    AWAIT_HUMAN_APPROVAL = "await_human_approval"
    EXECUTE_TOOL = "execute_tool"
    SAFE_TERMINAL = "safe_terminal"
    EVALUATE = "evaluate"
    PERSIST = "persist"
    EXPORT = "export"


class TelemetryOutcome(StrEnum):
    SUCCESS = "success"
    ABSTAINED = "abstained"
    DENIED = "denied"
    REJECTED = "rejected"
    TIMEOUT = "timeout"
    BUDGET_EXCEEDED = "budget_exceeded"
    CANCELLED = "cancelled"
    ERROR = "error"


class TelemetrySignal(StrEnum):
    TRACE = "trace"
    METRIC = "metric"
    LOG = "log"


class TelemetryEventName(StrEnum):
    STAGE_COMPLETED = "stage.completed"
    SECURITY_DECISION = "security.decision"
    APPROVAL_DECISION = "approval.decision"
    EXPORT_FAILURE = "telemetry.export_failure"
    RECORD_DROPPED = "telemetry.record_dropped"


class TokenType(StrEnum):
    INPUT = "input"
    OUTPUT = "output"
    TOTAL = "total"


class DropReason(StrEnum):
    CAPACITY = "capacity"
    EXPORT_FAILURE = "export_failure"
    INVALID_OBSERVATION = "invalid_observation"


APPROVED_TERMINAL_REASONS: Final = frozenset(
    {
        "insufficient_evidence",
        "no_authorized_evidence",
        "conflicting_evidence",
        "malformed_evidence",
        "invalid_generated_citation",
        "answer_reference_ready",
        "read_tool_completed",
        "approval_required",
        "write_tool_completed",
        "authorization_denied",
        "approval_rejected",
        "approval_expired",
        "approval_cancelled",
        "approval_conflict",
        "step_budget_exceeded",
        "tool_budget_exceeded",
        "provider_budget_exceeded",
        "token_budget_exceeded",
        "state_budget_exceeded",
        "deadline_exceeded",
        "evidence_not_authorized",
        "evidence_insufficient",
        "safe_failure",
    }
)

APPROVED_SAFE_ERROR_CODES: Final = frozenset(
    {
        "api_unsupported_media_type",
        "api_request_too_large",
        "api_request_malformed",
        "api_request_invalid",
        "authentication_not_configured",
        "authentication_required",
        "authentication_invalid",
        "authorization_denied",
        "api_query_deadline_exceeded",
        "api_overloaded",
        "service_not_ready",
        "agent_disabled",
        "agent_not_configured",
        "agent_approval_conflict",
        "agent_approval_expired",
        "agent_deadline_exceeded",
        "agent_overloaded",
        "agent_state_unavailable",
        "agent_budget_exceeded",
        "guardrail_input_invalid",
        "vector_store_validation",
        "vector_store_collection_mismatch",
        "vector_store_authorization_denied",
        "vector_store_timeout",
        "vector_store_unavailable",
        "embedding_error",
        "embedding_input_invalid",
        "embedding_batch_size_invalid",
        "embedding_input_too_long",
        "embedding_model_load_failed",
        "embedding_execution_failed",
        "embedding_contract_mismatch",
        "embedding_provider_failure",
        "rag_configuration_invalid",
        "rag_output_invalid",
        "llm_invalid_request",
        "llm_malformed_response",
        "llm_authentication_failed",
        "llm_authorization_failed",
        "llm_timeout",
        "llm_throttled",
        "llm_unavailable",
        "api_not_found",
        "api_method_not_allowed",
        "internal_error",
        "telemetry_export_failed",
        "telemetry_capacity_exceeded",
        "telemetry_observation_invalid",
    }
)

APPROVED_PROMPT_VERSIONS: Final = frozenset({"w3-001.v1"})
APPROVED_GRAPH_VERSIONS: Final = frozenset({"w4-002.graph.v1"})
APPROVED_TOOL_NAMES: Final = frozenset({"get_service_status", "mock_set_service_mode"})
APPROVED_TOOL_VERSIONS: Final = frozenset({"1.0"})


class TelemetryModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class SafeTelemetryAttributes(TelemetryModel):
    """Only finite, low-cardinality attributes accepted by telemetry sinks."""

    stage: TelemetryStage
    operation: TelemetryOperation
    outcome: TelemetryOutcome | None = None
    terminal_reason: str | None = Field(default=None, max_length=64)
    safe_error_code: str | None = Field(default=None, max_length=MAX_SAFE_CODE_LENGTH)
    prompt_version: str | None = Field(default=None, max_length=32)
    graph_version: str | None = Field(default=None, max_length=32)
    tool_name: str | None = Field(default=None, max_length=32)
    tool_version: str | None = Field(default=None, max_length=16)
    token_type: TokenType | None = None
    signal: TelemetrySignal | None = None
    drop_reason: DropReason | None = None

    @field_validator("terminal_reason")
    @classmethod
    def require_approved_terminal_reason(cls, value: str | None) -> str | None:
        if value is not None and value not in APPROVED_TERMINAL_REASONS:
            raise ValueError("terminal_reason is not approved")
        return value

    @field_validator("safe_error_code")
    @classmethod
    def require_approved_safe_error_code(cls, value: str | None) -> str | None:
        if value is not None and value not in APPROVED_SAFE_ERROR_CODES:
            raise ValueError("safe_error_code is not approved")
        return value

    @field_validator("prompt_version")
    @classmethod
    def require_approved_prompt_version(cls, value: str | None) -> str | None:
        if value is not None and value not in APPROVED_PROMPT_VERSIONS:
            raise ValueError("prompt_version is not approved")
        return value

    @field_validator("graph_version")
    @classmethod
    def require_approved_graph_version(cls, value: str | None) -> str | None:
        if value is not None and value not in APPROVED_GRAPH_VERSIONS:
            raise ValueError("graph_version is not approved")
        return value

    @field_validator("tool_name")
    @classmethod
    def require_approved_tool_name(cls, value: str | None) -> str | None:
        if value is not None and value not in APPROVED_TOOL_NAMES:
            raise ValueError("tool_name is not approved")
        return value

    @field_validator("tool_version")
    @classmethod
    def require_approved_tool_version(cls, value: str | None) -> str | None:
        if value is not None and value not in APPROVED_TOOL_VERSIONS:
            raise ValueError("tool_version is not approved")
        return value

    @model_validator(mode="after")
    def require_bound_pairs(self) -> SafeTelemetryAttributes:
        if (self.tool_name is None) != (self.tool_version is None):
            raise ValueError("tool name and version must be supplied together")
        return self

    def metric_attributes(self) -> dict[str, str]:
        """Return only approved, low-cardinality string metric labels."""

        values = self.model_dump(mode="json", exclude_none=True)
        return {key: str(value) for key, value in values.items()}


class SafeLogRecord(TelemetryModel):
    schema_version: Literal["w4-003.telemetry.v1"] = TELEMETRY_SCHEMA_VERSION
    timestamp_unix_nano: int = Field(ge=0)
    event_name: TelemetryEventName
    service_name: str = Field(
        min_length=1,
        max_length=MAX_SERVICE_NAME_LENGTH,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    request_id: UUID | None = None
    trace_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")
    span_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    stage: TelemetryStage
    operation: TelemetryOperation
    outcome: TelemetryOutcome
    terminal_reason: str | None = Field(default=None, max_length=64)
    safe_error_code: str | None = Field(default=None, max_length=MAX_SAFE_CODE_LENGTH)
    duration_ms: float | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    result_count: int | None = Field(default=None, ge=0)
    step_count: int | None = Field(default=None, ge=0, le=8)
    tool_call_count: int | None = Field(default=None, ge=0, le=1)
    prompt_version: str | None = Field(default=None, max_length=32)
    graph_version: str | None = Field(default=None, max_length=32)
    tool_name: str | None = Field(default=None, max_length=32)
    tool_version: str | None = Field(default=None, max_length=16)

    @field_validator("duration_ms")
    @classmethod
    def require_finite_duration(cls, value: float | None) -> float | None:
        if value is not None and not math.isfinite(value):
            raise ValueError("duration must be finite")
        return value

    @field_validator("terminal_reason")
    @classmethod
    def validate_terminal_reason(cls, value: str | None) -> str | None:
        return SafeTelemetryAttributes.require_approved_terminal_reason(value)

    @field_validator("safe_error_code")
    @classmethod
    def validate_safe_error_code(cls, value: str | None) -> str | None:
        return SafeTelemetryAttributes.require_approved_safe_error_code(value)

    @field_validator("prompt_version")
    @classmethod
    def validate_prompt_version(cls, value: str | None) -> str | None:
        return SafeTelemetryAttributes.require_approved_prompt_version(value)

    @field_validator("graph_version")
    @classmethod
    def validate_graph_version(cls, value: str | None) -> str | None:
        return SafeTelemetryAttributes.require_approved_graph_version(value)

    @field_validator("tool_name")
    @classmethod
    def validate_tool_name(cls, value: str | None) -> str | None:
        return SafeTelemetryAttributes.require_approved_tool_name(value)

    @field_validator("tool_version")
    @classmethod
    def validate_tool_version(cls, value: str | None) -> str | None:
        return SafeTelemetryAttributes.require_approved_tool_version(value)

    @model_validator(mode="after")
    def validate_counts_and_context(self) -> SafeLogRecord:
        token_values = (self.input_tokens, self.output_tokens, self.total_tokens)
        if any(value is not None for value in token_values):
            input_tokens, output_tokens, total_tokens = token_values
            if input_tokens is None or output_tokens is None or total_tokens is None:
                raise ValueError("token counts must be supplied together")
            if total_tokens != input_tokens + output_tokens:
                raise ValueError("token counts are inconsistent")
        if (self.trace_id is None) != (self.span_id is None):
            raise ValueError("trace and span identifiers must be supplied together")
        if (self.tool_name is None) != (self.tool_version is None):
            raise ValueError("tool name and version must be supplied together")
        return self


METRIC_NAMES: Final = {
    "stage_executions": "enterprise_ai.stage.executions",
    "stage_duration": "enterprise_ai.stage.duration",
    "usage_tokens": "enterprise_ai.usage.tokens",
    "retrieval_results": "enterprise_ai.retrieval.results",
    "agent_steps": "enterprise_ai.agent.steps",
    "agent_tool_calls": "enterprise_ai.agent.tool.calls",
    "export_failures": "enterprise_ai.telemetry.export.failures",
    "dropped": "enterprise_ai.telemetry.dropped",
}

METRIC_SERIES_UPPER_BOUND: Final = (
    len(METRIC_NAMES)
    * len(TelemetryStage)
    * len(TelemetryOperation)
    * (len(TelemetryOutcome) + 1)
    * (len(APPROVED_TERMINAL_REASONS) + 1)
    * (len(APPROVED_SAFE_ERROR_CODES) + 1)
    * (len(APPROVED_PROMPT_VERSIONS) + 1)
    * (len(APPROVED_GRAPH_VERSIONS) + 1)
    * (len(APPROVED_TOOL_NAMES) + 1)
    * (len(APPROVED_TOOL_VERSIONS) + 1)
    * (len(TokenType) + 1)
    * (len(TelemetrySignal) + 1)
    * (len(DropReason) + 1)
)

SPAN_NAMES: Final = {
    (TelemetryStage.API, TelemetryOperation.REQUEST): "enterprise_ai.api.request",
    (
        TelemetryStage.AUTHENTICATION,
        TelemetryOperation.AUTHENTICATE,
    ): "enterprise_ai.auth.authenticate",
    (
        TelemetryStage.AUTHORIZATION,
        TelemetryOperation.AUTHORIZE,
    ): "enterprise_ai.auth.authorize",
    (
        TelemetryStage.GUARDRAIL,
        TelemetryOperation.VALIDATE,
    ): "enterprise_ai.guardrail.validate",
    (TelemetryStage.RAG, TelemetryOperation.ANSWER): "enterprise_ai.rag.answer",
    (
        TelemetryStage.RETRIEVAL,
        TelemetryOperation.RETRIEVE,
    ): "enterprise_ai.retrieval.retrieve",
    (
        TelemetryStage.EMBEDDING,
        TelemetryOperation.EMBED_QUERY,
    ): "enterprise_ai.embedding.query",
    (
        TelemetryStage.EMBEDDING,
        TelemetryOperation.EMBED_DOCUMENTS,
    ): "enterprise_ai.embedding.documents",
    (
        TelemetryStage.VECTOR_SEARCH,
        TelemetryOperation.SEARCH,
    ): "enterprise_ai.vector.search",
    (TelemetryStage.LLM, TelemetryOperation.CHAT): "enterprise_ai.llm.chat",
    (TelemetryStage.AGENT, TelemetryOperation.HANDLE): "enterprise_ai.agent.handle",
    (
        TelemetryStage.APPROVAL,
        TelemetryOperation.EVALUATE,
    ): "enterprise_ai.approval.evaluate",
    (
        TelemetryStage.APPROVAL,
        TelemetryOperation.PERSIST,
    ): "enterprise_ai.approval.persist",
    (TelemetryStage.TOOL, TelemetryOperation.EXECUTE_TOOL): "enterprise_ai.tool.execute",
    (TelemetryStage.TELEMETRY, TelemetryOperation.EXPORT): "enterprise_ai.telemetry.export",
}

for _operation in (
    TelemetryOperation.VALIDATE_INPUT,
    TelemetryOperation.AUTHORIZE,
    TelemetryOperation.RETRIEVE,
    TelemetryOperation.GRADE_EVIDENCE,
    TelemetryOperation.ANSWER,
    TelemetryOperation.PROPOSE_TOOL,
    TelemetryOperation.AWAIT_HUMAN_APPROVAL,
    TelemetryOperation.EXECUTE_TOOL,
    TelemetryOperation.SAFE_TERMINAL,
):
    SPAN_NAMES[(TelemetryStage.GRAPH, _operation)] = f"enterprise_ai.agent.{_operation.value}"

TELEMETRY_ATTRIBUTE_ALLOWLIST: Final = frozenset(SafeTelemetryAttributes.model_fields)
STRUCTURED_LOG_FIELD_ALLOWLIST: Final = frozenset(SafeLogRecord.model_fields)
