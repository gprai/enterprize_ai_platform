"""Immutable provider-neutral request, response, usage, and tool models."""

from __future__ import annotations

import math
from enum import StrEnum
from typing import Any, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_ai_platform.json_contracts import JSONValue, defensive_json_copy


class LLMModel(BaseModel):
    """Strict immutable base for data crossing an LLM provider boundary."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class ChatRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


StopReason: TypeAlias = Literal[
    "end_turn",
    "tool_use",
    "max_tokens",
    "stop_sequence",
    "guardrail_intervened",
    "content_filtered",
    "model_context_window_exceeded",
]


class ChatMessage(LLMModel):
    role: ChatRole
    content: str = Field(min_length=1, max_length=1_000_000)


class ToolSpec(LLMModel):
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    description: str = Field(min_length=1, max_length=2000)
    input_schema: dict[str, JSONValue]

    @field_validator("input_schema", mode="before")
    @classmethod
    def detach_input_schema(cls, value: Any) -> Any:
        return defensive_json_copy(value)


class ToolCall(LLMModel):
    tool_call_id: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    arguments: dict[str, JSONValue]

    @field_validator("arguments", mode="before")
    @classmethod
    def detach_arguments(cls, value: Any) -> Any:
        return defensive_json_copy(value)


class ToolResult(LLMModel):
    tool_call_id: str = Field(min_length=1, max_length=256)
    content: JSONValue
    is_error: bool = False

    @field_validator("content", mode="before")
    @classmethod
    def detach_content(cls, value: Any) -> Any:
        return defensive_json_copy(value)


class Usage(LLMModel):
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost_usd: float | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_totals(self) -> Usage:
        if self.total_tokens != self.input_tokens + self.output_tokens:
            raise ValueError("total_tokens must equal input_tokens plus output_tokens")
        if self.estimated_cost_usd is not None and not math.isfinite(self.estimated_cost_usd):
            raise ValueError("estimated_cost_usd must be finite")
        return self


class ChatRequest(LLMModel):
    messages: tuple[ChatMessage, ...] = Field(min_length=1, max_length=100)
    tools: tuple[ToolSpec, ...] = Field(default=(), max_length=100)
    tool_results: tuple[ToolResult, ...] = Field(default=(), max_length=100)
    max_output_tokens: int = Field(default=512, ge=1, le=8192)

    @model_validator(mode="after")
    def require_unique_tool_names(self) -> ChatRequest:
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        return self


class ChatResponse(LLMModel):
    text: str = Field(default="", max_length=1_000_000)
    tool_calls: tuple[ToolCall, ...] = Field(default=(), max_length=100)
    usage: Usage | None = None
    stop_reason: StopReason | None = None

    @model_validator(mode="after")
    def require_content_or_tool_call(self) -> ChatResponse:
        if not self.text and not self.tool_calls:
            raise ValueError("a response requires text or a tool call")
        return self
