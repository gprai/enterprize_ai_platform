"""Provider-neutral embedding interfaces and compatibility checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from enterprise_ai_platform.embeddings.errors import EmbeddingContractMismatchError

EmbeddingVector = tuple[float, ...]
EmbeddingOperation = Literal["documents", "query"]
EmbeddingOutcome = Literal["success", "failure"]


@dataclass(frozen=True, slots=True)
class EmbeddingMetric:
    """Privacy-safe measurements for one embedding operation."""

    operation: EmbeddingOperation
    item_count: int
    batch_count: int
    duration_seconds: float
    outcome: EmbeddingOutcome


@runtime_checkable
class EmbeddingMetricRecorder(Protocol):
    """Receives aggregate metrics that never contain source text."""

    def record(self, metric: EmbeddingMetric) -> None:
        """Record one completed embedding operation."""


class NullEmbeddingMetricRecorder:
    """Default recorder used when telemetry is not configured."""

    def record(self, metric: EmbeddingMetric) -> None:
        """Intentionally discard the aggregate metric."""


@runtime_checkable
class Embedder(Protocol):
    """Asynchronous boundary shared by real and fake embedding providers."""

    @property
    def model_id(self) -> str: ...

    @property
    def model_revision(self) -> str: ...

    @property
    def dimension(self) -> int: ...

    @property
    def normalized(self) -> bool: ...

    async def embed_documents(self, texts: list[str]) -> tuple[EmbeddingVector, ...]: ...

    async def embed_query(self, text: str) -> EmbeddingVector: ...


@dataclass(frozen=True, slots=True)
class EmbeddingContract:
    """Embedding identity that a vector collection is built to accept."""

    model_id: str
    model_revision: str
    dimension: int
    normalized: bool
    metric: str


def assert_embedding_contract(
    embedder: Embedder,
    expected: EmbeddingContract,
) -> None:
    """Fail before vector-store access when provider and collection differ."""

    if (
        embedder.model_id != expected.model_id
        or embedder.model_revision != expected.model_revision
        or embedder.dimension != expected.dimension
        or embedder.normalized is not expected.normalized
        or expected.metric.lower() != "cosine"
    ):
        raise EmbeddingContractMismatchError
