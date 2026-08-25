"""Provider-neutral embedding contracts and implementations."""

from enterprise_ai_platform.embeddings.base import (
    Embedder,
    EmbeddingContract,
    EmbeddingMetric,
    EmbeddingMetricRecorder,
    EmbeddingVector,
    assert_embedding_contract,
)
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingBatchSizeError,
    EmbeddingContractMismatchError,
    EmbeddingError,
    EmbeddingExecutionError,
    EmbeddingInputError,
    EmbeddingInputTooLongError,
    EmbeddingModelLoadError,
    EmbeddingProviderFailure,
)
from enterprise_ai_platform.embeddings.fake import FakeEmbeddingProvider
from enterprise_ai_platform.embeddings.sentence_transformer import (
    SentenceTransformerEmbedder,
)

__all__ = [
    "Embedder",
    "EmbeddingBatchSizeError",
    "EmbeddingContract",
    "EmbeddingContractMismatchError",
    "EmbeddingError",
    "EmbeddingExecutionError",
    "EmbeddingInputError",
    "EmbeddingInputTooLongError",
    "EmbeddingMetric",
    "EmbeddingMetricRecorder",
    "EmbeddingModelLoadError",
    "EmbeddingProviderFailure",
    "EmbeddingVector",
    "FakeEmbeddingProvider",
    "SentenceTransformerEmbedder",
    "assert_embedding_contract",
]
