"""Strict public result models for cited answers and safe abstention."""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from enterprise_ai_platform.llm.models import Usage
from enterprise_ai_platform.rag.config import RAGPromptVersion
from enterprise_ai_platform.retrieval.models import Answer

type AbstentionReason = Literal[
    "insufficient_evidence",
    "no_authorized_evidence",
    "conflicting_evidence",
    "malformed_evidence",
    "invalid_generated_citation",
]


class RAGResultModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class CitedAnswerResult(RAGResultModel):
    outcome: Literal["answered"] = "answered"
    answer: Answer
    prompt_version: RAGPromptVersion = "w3-001.v1"
    usage: Usage | None = None

    @model_validator(mode="after")
    def require_cited_answer(self) -> CitedAnswerResult:
        if self.answer.abstained:
            raise ValueError("a cited result cannot contain an abstention")
        return self


class AbstentionResult(RAGResultModel):
    outcome: Literal["abstained"] = "abstained"
    reason: AbstentionReason
    prompt_version: RAGPromptVersion = "w3-001.v1"
    usage: Usage | None = None


type RAGResult = Annotated[
    CitedAnswerResult | AbstentionResult,
    Field(discriminator="outcome"),
]
