"""Explicit provider selection with no automatic fallback."""

from __future__ import annotations

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.llm.bedrock import BedrockLLMProvider, BedrockRuntimeClient
from enterprise_ai_platform.llm.errors import LLMValidationError
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.provider import LLMProvider


def create_llm_provider(
    settings: Settings,
    *,
    bedrock_client: BedrockRuntimeClient | None = None,
) -> LLMProvider:
    """Create exactly the configured provider without probing or fallback."""

    if settings.llm_provider == "fake":
        return FakeLLMProvider()
    if settings.llm_model_id is None or settings.aws_region is None:
        raise LLMValidationError
    return BedrockLLMProvider(
        model_id=settings.llm_model_id,
        region=settings.aws_region,
        client=bedrock_client,
    )
