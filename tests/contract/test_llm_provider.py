"""Contract tests for provider-neutral LLM requests, responses, and tools."""

from __future__ import annotations

import inspect

from enterprise_ai_platform.llm.models import (
    ChatRequest,
    ChatResponse,
    ToolCall,
    ToolResult,
    ToolSpec,
    Usage,
)
from enterprise_ai_platform.llm.provider import LLMProvider


def test_provider_exposes_one_async_chat_operation() -> None:
    public_functions = {
        name: member
        for name, member in inspect.getmembers(LLMProvider, inspect.isfunction)
        if not name.startswith("_")
    }

    assert set(public_functions) == {"chat"}
    assert inspect.iscoroutinefunction(public_functions["chat"])


def test_models_are_strict_closed_schemas_without_reasoning() -> None:
    for model in (ChatRequest, ChatResponse, ToolSpec, ToolCall, ToolResult, Usage):
        schema = model.model_json_schema()
        assert schema["additionalProperties"] is False
        assert "reasoning" not in repr(schema).casefold()


def test_usage_cost_is_nullable_but_token_totals_are_required() -> None:
    schema = Usage.model_json_schema()

    assert set(schema["required"]) == {"input_tokens", "output_tokens", "total_tokens"}
    assert "estimated_cost_usd" not in schema["required"]
