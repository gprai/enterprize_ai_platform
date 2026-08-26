"""Cleanliness tests for import-time and fake-mode residual resources."""

from __future__ import annotations

import importlib
import threading

from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.llm import bedrock
from enterprise_ai_platform.llm.factory import create_llm_provider
from enterprise_ai_platform.llm.fake import FakeLLMProvider
from enterprise_ai_platform.llm.provider import PROCESS_WIDE_PROVIDER_CALL_GATE


def test_import_creates_no_thread_executor_or_provider_call() -> None:
    before = {thread.ident for thread in threading.enumerate()}

    importlib.reload(bedrock)

    after = {thread.ident for thread in threading.enumerate()}
    assert after == before
    assert PROCESS_WIDE_PROVIDER_CALL_GATE.active_calls == 0
    assert PROCESS_WIDE_PROVIDER_CALL_GATE.max_active_calls == 4


def test_fake_mode_leaves_no_client_credential_or_model_resource() -> None:
    settings = Settings(
        _env_file=None,
        llm_provider="fake",
        llm_model_id=None,
        aws_region=None,
        embedding_model_id="sentence-transformers/all-MiniLM-L6-v2",
        qdrant_url="http://127.0.0.1:6333",
        opensearch_url="https://opensearch.invalid",
    )

    provider = create_llm_provider(settings)

    assert isinstance(provider, FakeLLMProvider)
    assert not hasattr(provider, "_client")
    assert settings.llm_model_id is None
    assert settings.aws_region is None
