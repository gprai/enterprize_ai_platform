"""Local integration tests for settings, factory, and injected Bedrock Converse client."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.llm.bedrock import BedrockLLMProvider
from enterprise_ai_platform.llm.factory import create_llm_provider
from enterprise_ai_platform.llm.models import ChatMessage, ChatRequest, ChatRole

pytestmark = [pytest.mark.integration, pytest.mark.aws, pytest.mark.paid]


class InjectedConverseClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def converse(self, **kwargs: object) -> Mapping[str, object]:
        self.calls.append(dict(kwargs))
        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": '{"answer":"Synthetic answer","citations":[]}'}],
                }
            },
            "usage": {"inputTokens": 5, "outputTokens": 4, "totalTokens": 9},
            "stopReason": "end_turn",
        }


def test_explicit_bedrock_selection_uses_only_injected_converse_client() -> None:
    client = InjectedConverseClient()
    settings = Settings(
        _env_file=None,
        llm_provider="bedrock",
        llm_model_id="synthetic.model-v1",
        aws_region="ap-southeast-1",
        embedding_model_id="sentence-transformers/all-MiniLM-L6-v2",
        qdrant_url="http://127.0.0.1:6333",
        opensearch_url="https://opensearch.invalid",
    )

    provider = create_llm_provider(settings, bedrock_client=client)

    assert isinstance(provider, BedrockLLMProvider)
    assert client.calls == []
    response = asyncio.run(
        provider.chat(
            ChatRequest(messages=(ChatMessage(role=ChatRole.USER, content="Synthetic question"),))
        )
    )
    assert response.usage is not None and response.usage.total_tokens == 9
    assert len(client.calls) == 1
    assert set(client.calls[0]) == {"modelId", "messages", "inferenceConfig"}
