"""Unit tests for provider-neutral LLM contracts and fake-mode isolation."""

from __future__ import annotations

import asyncio
import threading

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.llm.factory import create_llm_provider
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.models import (
    ChatMessage,
    ChatRequest,
    ChatResponse,
    ChatRole,
    ToolCall,
    ToolResult,
    ToolSpec,
)
from enterprise_ai_platform.llm.provider import LLMProvider, ProviderCallGate


def _request() -> ChatRequest:
    return ChatRequest(messages=(ChatMessage(role=ChatRole.USER, content="synthetic question"),))


def test_tool_json_is_defensively_copied() -> None:
    schema = {"type": "object", "properties": {"name": {"type": "string"}}}
    arguments = {"name": "synthetic"}
    result_content = {"accepted": True}

    tool = ToolSpec(name="lookup", description="Synthetic lookup", input_schema=schema)
    call = ToolCall(tool_call_id="call-1", name="lookup", arguments=arguments)
    result = ToolResult(tool_call_id="call-1", content=result_content)
    schema["type"] = "array"
    arguments["name"] = "changed"
    result_content["accepted"] = False

    assert tool.input_schema["type"] == "object"
    assert call.arguments["name"] == "synthetic"
    assert result.content == {"accepted": True}


def test_tool_json_rejects_non_json_keys_and_non_finite_numbers() -> None:
    with pytest.raises(TypeError):
        ToolSpec(
            name="lookup",
            description="Synthetic lookup",
            input_schema={1: "not-a-string-key"},
        )
    with pytest.raises(ValueError):
        ToolCall(
            tool_call_id="call-1",
            name="lookup",
            arguments={"score": float("inf")},
        )


def test_contracts_reject_unknown_fields_and_expose_no_reasoning_field() -> None:
    with pytest.raises(ValidationError):
        ChatResponse(text="synthetic", reasoning="private")

    assert "reasoning" not in ChatResponse.model_json_schema()["properties"]


def test_fake_provider_is_deterministic_and_satisfies_protocol() -> None:
    provider = FakeLLMProvider()

    first = asyncio.run(provider.chat(_request()))
    second = asyncio.run(provider.chat(_request()))

    assert isinstance(provider, LLMProvider)
    assert first == second
    assert len(provider.requests) == 2


def test_fake_factory_requires_no_bedrock_client_or_aws_values() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="fake",
        llm_model_id="",
        aws_region="",
        embedding_model_id="sentence-transformers/all-MiniLM-L6-v2",
        qdrant_url="http://127.0.0.1:6333",
        opensearch_url="https://opensearch.invalid",
    )

    assert isinstance(create_llm_provider(settings), FakeLLMProvider)
    assert settings.llm_model_id is None
    assert settings.aws_region is None


def test_provider_call_gate_enforces_fixed_limit_and_cancelled_waiter() -> None:
    gate = ProviderCallGate(max_active_calls=4)
    tokens = [threading.Event() for _ in range(4)]

    assert all(gate.acquire(token) for token in tokens)
    cancelled = threading.Event()
    cancelled.set()
    assert gate.acquire(cancelled) is False
    assert gate.active_calls == 4

    for _ in tokens:
        gate.release()
    assert gate.active_calls == 0
