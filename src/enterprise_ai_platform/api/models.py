"""Strict transport, response, and error schemas for W4-001."""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

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
