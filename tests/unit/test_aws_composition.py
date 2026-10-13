"""Unit coverage for bounded W6-004 AWS startup and retrieval budgets."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

import enterprise_ai_platform.api.aws_composition as composition_module
from enterprise_ai_platform.api.aws_composition import (
    AWS_CONNECT_TIMEOUT_SECONDS,
    AWS_READ_TIMEOUT_SECONDS,
    AWS_RETRIEVAL_TIMEOUT_SECONDS,
    AWS_STARTUP_WARMUP_TEXT,
    RUNTIME_CONFIGURATION_HASHES,
    AWSRuntimeComposition,
    compose_aws_runtime,
)
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.retrieval.models import APPROVED_EMBEDDING_DIMENSION
from enterprise_ai_platform.telemetry.runtime import NullTelemetryRuntime


class FakeEmbedder:
    model_id = "sentence-transformers/all-MiniLM-L6-v2"
    model_revision = "".join(("1110a243", "fdf4706b", "3f48f1d9", "5db1a4f5", "529b4d41"))
    dimension = APPROVED_EMBEDDING_DIMENSION
    normalized = True

    def __init__(self, *, block: bool = False) -> None:
        self.block = block
        self.queries: list[str] = []

    async def embed_query(self, text: str) -> tuple[float, ...]:
        self.queries.append(text)
        if self.block:
            await asyncio.Event().wait()
        return (1.0, *([0.0] * (APPROVED_EMBEDDING_DIMENSION - 1)))

    async def embed_documents(self, texts: list[str]) -> tuple[tuple[float, ...], ...]:
        return tuple([await self.embed_query(text) for text in texts])


class FakeOpenSearchClient:
    async def close(self) -> None:
        return None


def _runtime(embedder: FakeEmbedder) -> AWSRuntimeComposition:
    return AWSRuntimeComposition(
        rag_service=object(),  # type: ignore[arg-type]
        readiness_probe=object(),  # type: ignore[arg-type]
        telemetry=NullTelemetryRuntime(),
        opensearch_client=FakeOpenSearchClient(),
        embedder=embedder,
    )


def test_runtime_warms_the_exact_local_embedding_path_before_service() -> None:
    embedder = FakeEmbedder()

    asyncio.run(_runtime(embedder).start())

    assert embedder.queries == [AWS_STARTUP_WARMUP_TEXT]


def test_runtime_warmup_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    embedder = FakeEmbedder(block=True)
    monkeypatch.setattr(
        composition_module,
        "AWS_STARTUP_WARMUP_TIMEOUT_SECONDS",
        0.01,
    )

    with pytest.raises(TimeoutError):
        asyncio.run(_runtime(embedder).start())


def test_aws_runtime_uses_fifteen_second_retrieval_budget(
    monkeypatch: pytest.MonkeyPatch,
    valid_settings: Settings,
) -> None:
    captured: dict[str, Any] = {}

    class CapturingRetrievalService:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(
        composition_module,
        "RetrievalService",
        CapturingRetrievalService,
    )

    settings = valid_settings.model_copy(
        update={
            "aws_composition_enabled": True,
            "aws_region": "ap-southeast-1",
            "llm_model_id": "approved-inference-profile",
        }
    )
    embedder = FakeEmbedder()

    runtime = compose_aws_runtime(
        settings,
        opensearch_client=FakeOpenSearchClient(),
        bedrock_client=object(),  # type: ignore[arg-type]
        embedder=embedder,
        telemetry=NullTelemetryRuntime(),  # type: ignore[arg-type]
    )

    assert captured["timeout_seconds"] == AWS_RETRIEVAL_TIMEOUT_SECONDS == 15.0
    assert runtime.embedder is embedder
    assert runtime.configuration_hashes == RUNTIME_CONFIGURATION_HASHES
    assert runtime.configuration_hashes.model_config_sha256 == "".join(
        (
            "36ea47e1",
            "3ee1109f",
            "5500b7c4",
            "74ac0452",
            "4404b98f",
            "6fae3600",
            "5aa37dbe",
            "cc2d558f",
        )
    )
    assert AWS_CONNECT_TIMEOUT_SECONDS == 3
    assert AWS_READ_TIMEOUT_SECONDS == 20
