from __future__ import annotations

import asyncio
import hashlib
import math
import os
import threading
from pathlib import Path
from typing import Any

import pytest

from enterprise_ai_platform.embeddings.base import EmbeddingMetric
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingBatchSizeError,
    EmbeddingInputError,
    EmbeddingInputTooLongError,
)
from enterprise_ai_platform.embeddings.sentence_transformer import (
    APPROVED_SAFETENSORS_SHA256,
    APPROVED_SAFETENSORS_SIZE,
    APPROVED_SNAPSHOT_FILES,
    SentenceTransformerEmbedder,
)

pytestmark = pytest.mark.integration
APPROVED_CACHE_ROOT = Path(r"E:\AI\.model-cache\enterprise_ai_platform\W2-002")
NORMALIZED_VECTOR = [1.0, *([0.0] * 383)]


class MetricSpy:
    def __init__(self) -> None:
        self.metrics: list[EmbeddingMetric] = []

    def record(self, metric: EmbeddingMetric) -> None:
        self.metrics.append(metric)


class StubTokenizer:
    def encode(
        self,
        text: str,
        *,
        add_special_tokens: bool,
        truncation: bool,
    ) -> list[int]:
        assert add_special_tokens is True
        assert truncation is False
        return [1, 2]


class ConcurrencyState:
    def __init__(self) -> None:
        self.guard = threading.Lock()
        self.release_first = threading.Event()
        self.first_started = threading.Event()
        self.first_finished = threading.Event()
        self.second_started = threading.Event()
        self.active = 0
        self.max_active = 0
        self.calls = 0


class ControlledModel:
    tokenizer = StubTokenizer()

    def __init__(self, state: ConcurrencyState) -> None:
        self._state = state

    def encode(self, texts: list[str], **kwargs: Any) -> list[list[float]]:
        assert kwargs["device"] == "cpu"
        assert kwargs["normalize_embeddings"] is True
        with self._state.guard:
            self._state.calls += 1
            call_number = self._state.calls
            self._state.active += 1
            self._state.max_active = max(
                self._state.max_active,
                self._state.active,
            )
        if call_number == 1:
            self._state.first_started.set()
        else:
            self._state.second_started.set()
        try:
            if call_number == 1:
                assert self._state.release_first.wait(timeout=5.0)
            return [NORMALIZED_VECTOR.copy() for _ in texts]
        finally:
            with self._state.guard:
                self._state.active -= 1
            if call_number == 1:
                self._state.first_finished.set()


def test_verified_sentence_transformer_snapshot_operates_offline_on_cpu() -> None:
    if os.environ.get("RUN_W2_002_REAL_MODEL_TEST") != "1":
        pytest.skip("Real-model test is owner-controlled and opt-in.")
    snapshot_value = os.environ.get("W2_002_MODEL_SNAPSHOT")
    if not snapshot_value:
        pytest.fail("W2_002_MODEL_SNAPSHOT must identify the verified snapshot.")
    assert os.environ.get("HF_HUB_OFFLINE") == "1"
    assert os.environ.get("TRANSFORMERS_OFFLINE") == "1"
    assert os.environ.get("CUDA_VISIBLE_DEVICES") == "-1"

    snapshot_path = Path(snapshot_value)
    assert snapshot_path.is_absolute()
    approved_root = APPROVED_CACHE_ROOT.resolve(strict=True)
    resolved_snapshot = snapshot_path.resolve(strict=True)
    assert resolved_snapshot.is_relative_to(approved_root)
    assert resolved_snapshot.name == ("1110a243fdf4706b3f48f1d95db1a4f5529b4d41")

    snapshot_files = {
        path.relative_to(resolved_snapshot).as_posix()
        for path in resolved_snapshot.rglob("*")
        if path.is_file()
    }
    assert snapshot_files == APPROVED_SNAPSHOT_FILES
    artifact = resolved_snapshot / "model.safetensors"
    assert artifact.stat().st_size == APPROVED_SAFETENSORS_SIZE
    with artifact.open("rb") as stream:
        assert hashlib.file_digest(stream, "sha256").hexdigest() == APPROVED_SAFETENSORS_SHA256

    for invalid_batch_size in (False, True, "32", 32.0, -1, 0, 129):
        with pytest.raises(EmbeddingBatchSizeError):
            SentenceTransformerEmbedder(
                resolved_snapshot,
                batch_size=invalid_batch_size,  # type: ignore[arg-type]
            )

    SentenceTransformerEmbedder(resolved_snapshot, batch_size=1)
    SentenceTransformerEmbedder(resolved_snapshot, batch_size=128)

    recorder = MetricSpy()
    provider = SentenceTransformerEmbedder(
        resolved_snapshot,
        metric_recorder=recorder,
    )
    assert provider.model_id == "sentence-transformers/all-MiniLM-L6-v2"
    assert provider.model_revision == ("1110a243fdf4706b3f48f1d95db1a4f5529b4d41")
    assert provider.dimension == 384
    assert provider.normalized is True

    with pytest.raises(EmbeddingInputError):
        asyncio.run(provider.embed_documents(["item"] * 1_025))

    vectors = asyncio.run(provider.embed_documents(["alpha", "beta"]))
    query = asyncio.run(provider.embed_query("alpha"))

    assert len(vectors) == 2
    assert all(len(vector) == 384 for vector in (*vectors, query))
    assert all(
        math.isclose(
            math.sqrt(sum(value * value for value in vector)),
            1.0,
            rel_tol=1e-5,
            abs_tol=1e-5,
        )
        for vector in (*vectors, query)
    )
    assert vectors[0] == pytest.approx(query, abs=1e-6)
    assert provider._model is not None
    assert str(provider._model.device) == "cpu"
    assert [metric.item_count for metric in recorder.metrics] == [2, 1]
    assert all(metric.duration_seconds >= 0.0 for metric in recorder.metrics)
    assert "alpha" not in repr(recorder.metrics)

    with pytest.raises(EmbeddingInputTooLongError):
        asyncio.run(provider.embed_query("token " * 300))

    state = ConcurrencyState()
    first_provider = SentenceTransformerEmbedder(resolved_snapshot)
    second_provider = SentenceTransformerEmbedder(resolved_snapshot)
    first_provider._model = ControlledModel(state)
    second_provider._model = ControlledModel(state)

    async def cancellation_scenario() -> None:
        first_task = asyncio.create_task(first_provider.embed_query("first"))
        assert await asyncio.to_thread(state.first_started.wait, 5.0)
        first_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first_task

        second_task = asyncio.create_task(second_provider.embed_query("second"))
        await asyncio.sleep(0.05)
        assert not state.second_started.is_set()

        state.release_first.set()
        assert await asyncio.to_thread(state.first_finished.wait, 5.0)
        second_vector = await asyncio.wait_for(second_task, timeout=5.0)
        assert len(second_vector) == 384

    asyncio.run(cancellation_scenario())
    assert state.calls == 2
    assert state.max_active == 1
