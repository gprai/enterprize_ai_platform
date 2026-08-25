"""Deterministic test-only embedding provider."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Sequence

from enterprise_ai_platform.embeddings.base import (
    EmbeddingMetric,
    EmbeddingMetricRecorder,
    EmbeddingVector,
    NullEmbeddingMetricRecorder,
)
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingInputError,
    EmbeddingProviderFailure,
)
from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
    APPROVED_EMBEDDING_MODEL_ID,
    APPROVED_EMBEDDING_REVISION,
)


class FakeEmbeddingProvider:
    """Produces repeatable normalized vectors without loading an ML model."""

    def __init__(
        self,
        *,
        fail: bool = False,
        model_id: str = APPROVED_EMBEDDING_MODEL_ID,
        model_revision: str = APPROVED_EMBEDDING_REVISION,
        dimension: int = APPROVED_EMBEDDING_DIMENSION,
        normalized: bool = True,
        metric_recorder: EmbeddingMetricRecorder | None = None,
    ) -> None:
        self._fail = fail
        self._model_id = model_id
        self._model_revision = model_revision
        self._dimension = dimension
        self._normalized = normalized
        self._metric_recorder = metric_recorder or NullEmbeddingMetricRecorder()

    @property
    def model_id(self) -> str:
        return self._model_id

    @property
    def model_revision(self) -> str:
        return self._model_revision

    @property
    def dimension(self) -> int:
        return self._dimension

    @property
    def normalized(self) -> bool:
        return self._normalized

    async def embed_documents(self, texts: list[str]) -> tuple[EmbeddingVector, ...]:
        self._validate(texts)
        if self._fail:
            self._record("documents", len(texts), "failure")
            raise EmbeddingProviderFailure
        vectors = tuple(self._vector(text) for text in texts)
        self._record("documents", len(texts), "success")
        return vectors

    async def embed_query(self, text: str) -> EmbeddingVector:
        self._validate((text,))
        if self._fail:
            self._record("query", 1, "failure")
            raise EmbeddingProviderFailure
        vector = self._vector(text)
        self._record("query", 1, "success")
        return vector

    def _validate(self, texts: Sequence[str]) -> None:
        if (
            not texts
            or len(texts) > 1_024
            or any(not isinstance(text, str) or not text.strip() for text in texts)
        ):
            raise EmbeddingInputError

    def _vector(self, text: str) -> EmbeddingVector:
        values: list[float] = []
        counter = 0
        while len(values) < self._dimension:
            digest = hashlib.sha256(
                text.encode("utf-8") + counter.to_bytes(4, "big")
            ).digest()
            values.extend((byte - 127.5) / 127.5 for byte in digest)
            counter += 1
        selected = values[: self._dimension]
        if not self._normalized:
            return tuple(selected)
        norm = math.sqrt(sum(value * value for value in selected))
        return tuple(value / norm for value in selected)

    def _record(
        self,
        operation: str,
        item_count: int,
        outcome: str,
    ) -> None:
        self._metric_recorder.record(
            EmbeddingMetric(
                operation="query" if operation == "query" else "documents",
                item_count=item_count,
                batch_count=1 if item_count else 0,
                duration_seconds=0.0,
                outcome="success" if outcome == "success" else "failure",
            )
        )
