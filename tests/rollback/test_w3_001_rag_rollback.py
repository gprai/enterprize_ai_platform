"""Rollback tests for explicit provider selection and no hidden fallback."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest
from botocore.exceptions import ClientError

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.llm.bedrock import BedrockLLMProvider
from enterprise_ai_platform.llm.errors import LLMAuthorizationError
from enterprise_ai_platform.llm.factory import create_llm_provider
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.models import ChatMessage, ChatRequest, ChatRole


class DeniedBedrockClient:
    def __init__(self) -> None:
        self.calls = 0

    def converse(self, **kwargs: object) -> Mapping[str, object]:
        self.calls += 1
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "sensitive"}},
            "Converse",
        )


def _settings(provider: str) -> Settings:
    return Settings(
        _env_file=None,
        llm_provider=provider,
        llm_model_id="synthetic.model-v1" if provider == "bedrock" else None,
        aws_region="ap-southeast-1" if provider == "bedrock" else None,
        embedding_model_id="sentence-transformers/all-MiniLM-L6-v2",
        qdrant_url="http://127.0.0.1:6333",
        opensearch_url="https://opensearch.invalid",
    )


def test_provider_failure_never_falls_back_and_fake_rollback_is_local() -> None:
    client = DeniedBedrockClient()
    selected = create_llm_provider(_settings("bedrock"), bedrock_client=client)
    request = ChatRequest(
        messages=(ChatMessage(role=ChatRole.USER, content="Synthetic question"),)
    )

    assert isinstance(selected, BedrockLLMProvider)
    with pytest.raises(LLMAuthorizationError):
        asyncio.run(selected.chat(request))
    assert client.calls == 1

    rolled_back = create_llm_provider(_settings("fake"), bedrock_client=client)
    assert isinstance(rolled_back, FakeLLMProvider)
    asyncio.run(rolled_back.chat(request))
    assert client.calls == 1
