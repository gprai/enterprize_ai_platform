"""Strict transport, response, and error schemas for W4-001."""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import UUID4, BaseModel, ConfigDict, Field

from enterprise_ai_platform.agent.models import (
    AgentOutcome,
    MockSetServiceModeArguments,
    TerminalReason,
)
from enterprise_ai_platform.llm.models import Usage
from enterprise_ai_platform.rag.models import AbstentionReason
from enterprise_ai_platform.retrieval.models import Citation


class APIModel(BaseModel):
    """Immutable strict model used only at the HTTP boundary."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class QueryRequest(APIModel):
    """Untrusted query transport; identity fields are intentionally absent."""

    query: str


class StartAgentRequest(APIModel):
    """Untrusted start command containing no identity or authority."""

    action: Literal["start"]
    query: str = Field(min_length=1, max_length=10_000)


class DecideAgentRequest(APIModel):
    """Exact approval command; trusted approver facts remain out-of-band."""

    action: Literal["decide"]
    approval_id: UUID4
    idempotency_key: UUID
    decision: Literal["approved"]
    tool_name: Literal["mock_set_service_mode"]
    tool_version: Literal["1.0"]
    arguments: MockSetServiceModeArguments


AgentRequest: TypeAlias = Annotated[
    StartAgentRequest | DecideAgentRequest,
    Field(discriminator="action"),
]


class LivenessResponse(APIModel):
    request_id: UUID
    status: Literal["ok"] = "ok"


class ReadinessResponse(APIModel):
    request_id: UUID
    status: Literal["ready"] = "ready"


class AnsweredQueryResponse(APIModel):
    request_id: UUID
    outcome: Literal["answered"] = "answered"
    answer: str
    citations: tuple[Citation, ...]
    prompt_version: str
    usage: Usage | None = None


class AbstainedQueryResponse(APIModel):
    request_id: UUID
    outcome: Literal["abstained"] = "abstained"
    reason: AbstentionReason
    prompt_version: str


QueryResponse: TypeAlias = Annotated[
    AnsweredQueryResponse | AbstainedQueryResponse,
    Field(discriminator="outcome"),
]


class APIErrorDetail(APIModel):
    code: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9_]+$")
    message: str = Field(min_length=1, max_length=500)
    retryable: bool | None = None


class APIErrorResponse(APIModel):
    request_id: UUID
    error: APIErrorDetail


class AgentResponse(APIModel):
    """Content-free normalized agent terminal or approval-required result."""

    request_id: UUID4
    run_id: UUID4
    outcome: AgentOutcome
    terminal_reason: TerminalReason
    approval_id: UUID4 | None = None
    result_reference_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    safe_error_code: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9_]+$",
    )
