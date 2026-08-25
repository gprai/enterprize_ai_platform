"""Offline, CPU-bounded Sentence Transformers embedding adapter."""

from __future__ import annotations

import asyncio
import hashlib
import importlib
import math
import os
import threading
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter
from typing import Any, cast

from enterprise_ai_platform.embeddings.base import (
    EmbeddingMetric,
    EmbeddingMetricRecorder,
    EmbeddingOperation,
    EmbeddingVector,
    NullEmbeddingMetricRecorder,
)
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingBatchSizeError,
    EmbeddingContractMismatchError,
    EmbeddingError,
    EmbeddingExecutionError,
    EmbeddingInputError,
    EmbeddingInputTooLongError,
    EmbeddingModelLoadError,
)
from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
    APPROVED_EMBEDDING_MODEL_ID,
    APPROVED_EMBEDDING_REVISION,
)

DEFAULT_BATCH_SIZE = 32
MAX_BATCH_SIZE = 128
MAX_ITEMS_PER_CALL = 1_024
MAX_INPUT_WORDPIECES = 256
APPROVED_SAFETENSORS_SIZE = 90_868_376
APPROVED_SAFETENSORS_SHA256 = (
    "53aa51172d142c89d9012cce15ae4d6cc0ca6895895114379cacb4fab128d9db"
)
APPROVED_SNAPSHOT_FILES = frozenset(
    {
        "1_Pooling/config.json",
        "README.md",
        "config.json",
        "config_sentence_transformers.json",
        "model.safetensors",
        "modules.json",
        "sentence_bert_config.json",
        "special_tokens_map.json",
        "tokenizer.json",
        "tokenizer_config.json",
        "vocab.txt",
    }
)
_CPU_OPERATION_LOCK = threading.Lock()


class SentenceTransformerEmbedder:
    """Loads only the verified local snapshot and performs serialized CPU inference."""

    def __init__(
        self,
        snapshot_path: Path,
        *,
        batch_size: int = DEFAULT_BATCH_SIZE,
        metric_recorder: EmbeddingMetricRecorder | None = None,
    ) -> None:
        if (
            isinstance(batch_size, bool)
            or not isinstance(batch_size, int)
            or not 1 <= batch_size <= MAX_BATCH_SIZE
        ):
            raise EmbeddingBatchSizeError
        self._snapshot_path = snapshot_path
        self._batch_size = batch_size
        self._metric_recorder = metric_recorder or NullEmbeddingMetricRecorder()
        self._operation_lock = asyncio.Lock()
        self._model: Any | None = None

    @property
    def model_id(self) -> str:
        return APPROVED_EMBEDDING_MODEL_ID

    @property
    def model_revision(self) -> str:
        return APPROVED_EMBEDDING_REVISION

    @property
    def dimension(self) -> int:
        return APPROVED_EMBEDDING_DIMENSION

    @property
    def normalized(self) -> bool:
        return True

    async def embed_documents(self, texts: list[str]) -> tuple[EmbeddingVector, ...]:
        return await self._embed(texts, "documents")

    async def embed_query(self, text: str) -> EmbeddingVector:
        vectors = await self._embed([text], "query")
        return vectors[0]

    async def _embed(
        self,
        texts: list[str],
        operation: EmbeddingOperation,
    ) -> tuple[EmbeddingVector, ...]:
        self._validate_items(texts)
        started = perf_counter()
        batch_count = math.ceil(len(texts) / self._batch_size)
        try:
            async with self._operation_lock:
                vectors = await asyncio.to_thread(self._embed_sync, tuple(texts))
        except EmbeddingError:
            self._record(operation, len(texts), batch_count, started, "failure")
            raise
        except Exception:
            self._record(operation, len(texts), batch_count, started, "failure")
            raise EmbeddingExecutionError from None
        self._record(operation, len(texts), batch_count, started, "success")
        return vectors

    def _embed_sync(self, texts: tuple[str, ...]) -> tuple[EmbeddingVector, ...]:
        with _CPU_OPERATION_LOCK:
            model = self._get_model()
            self._validate_token_lengths(model, texts)
            try:
                raw_vectors = model.encode(
                    list(texts),
                    batch_size=self._batch_size,
                    show_progress_bar=False,
                    output_value="sentence_embedding",
                    precision="float32",
                    convert_to_numpy=True,
                    convert_to_tensor=False,
                    device="cpu",
                    normalize_embeddings=True,
                )
            except Exception:
                raise EmbeddingExecutionError from None
            return self._validate_vectors(
                cast(Sequence[Sequence[float]], raw_vectors),
                len(texts),
            )

    def _get_model(self) -> Any:
        if self._model is not None:
            return self._model
        self._verify_offline_runtime()
        self._verify_snapshot()
        try:
            module = importlib.import_module("sentence_transformers")
            sentence_transformer = module.SentenceTransformer
            model = sentence_transformer(
                str(self._snapshot_path),
                device="cpu",
                token=False,
                local_files_only=True,
                trust_remote_code=False,
            )
        except Exception:
            raise EmbeddingModelLoadError from None
        if int(model.get_embedding_dimension()) != self.dimension:
            raise EmbeddingContractMismatchError
        if int(model.max_seq_length) != MAX_INPUT_WORDPIECES:
            raise EmbeddingContractMismatchError
        self._model = model
        return model

    def _verify_offline_runtime(self) -> None:
        if (
            os.environ.get("HF_HUB_OFFLINE") != "1"
            or os.environ.get("TRANSFORMERS_OFFLINE") != "1"
        ):
            raise EmbeddingModelLoadError

    def _verify_snapshot(self) -> None:
        if (
            not self._snapshot_path.is_absolute()
            or not self._snapshot_path.is_dir()
            or self._snapshot_path.name != self.model_revision
        ):
            raise EmbeddingModelLoadError
        files = {
            path.relative_to(self._snapshot_path).as_posix()
            for path in self._snapshot_path.rglob("*")
            if path.is_file()
        }
        if files != APPROVED_SNAPSHOT_FILES:
            raise EmbeddingModelLoadError
        artifact = self._snapshot_path / "model.safetensors"
        if artifact.stat().st_size != APPROVED_SAFETENSORS_SIZE:
            raise EmbeddingModelLoadError
        digest = hashlib.sha256()
        with artifact.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != APPROVED_SAFETENSORS_SHA256:
            raise EmbeddingModelLoadError

    def _validate_token_lengths(self, model: Any, texts: tuple[str, ...]) -> None:
        try:
            for text in texts:
                token_ids = model.tokenizer.encode(
                    text,
                    add_special_tokens=True,
                    truncation=False,
                )
                if len(token_ids) > MAX_INPUT_WORDPIECES:
                    raise EmbeddingInputTooLongError
        except EmbeddingInputTooLongError:
            raise
        except Exception:
            raise EmbeddingExecutionError from None

    def _validate_items(self, texts: list[str]) -> None:
        if not texts or len(texts) > MAX_ITEMS_PER_CALL:
            raise EmbeddingInputError
        if any(not isinstance(text, str) or not text.strip() for text in texts):
            raise EmbeddingInputError

    def _validate_vectors(
        self,
        vectors: Sequence[Sequence[float]],
        expected_count: int,
    ) -> tuple[EmbeddingVector, ...]:
        if len(vectors) != expected_count:
            raise EmbeddingContractMismatchError
        checked: list[EmbeddingVector] = []
        for raw_vector in vectors:
            vector = tuple(float(value) for value in raw_vector)
            norm = math.sqrt(sum(value * value for value in vector))
            if (
                len(vector) != self.dimension
                or not all(math.isfinite(value) for value in vector)
                or not math.isclose(norm, 1.0, rel_tol=1e-5, abs_tol=1e-5)
            ):
                raise EmbeddingContractMismatchError
            checked.append(vector)
        return tuple(checked)

    def _record(
        self,
        operation: EmbeddingOperation,
        item_count: int,
        batch_count: int,
        started: float,
        outcome: str,
    ) -> None:
        self._metric_recorder.record(
            EmbeddingMetric(
                operation=operation,
                item_count=item_count,
                batch_count=batch_count,
                duration_seconds=perf_counter() - started,
                outcome="success" if outcome == "success" else "failure",
            )
        )
