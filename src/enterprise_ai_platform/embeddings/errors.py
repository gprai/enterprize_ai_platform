"""Stable, privacy-safe failures for the embedding boundary."""


class EmbeddingError(Exception):
    """Base error whose public message cannot disclose input text."""

    code = "embedding_error"
    public_message = "The embedding operation failed."

    def __init__(self) -> None:
        super().__init__(self.public_message)


class EmbeddingInputError(EmbeddingError):
    code = "embedding_input_invalid"
    public_message = "The embedding input is invalid."


class EmbeddingBatchSizeError(EmbeddingError):
    code = "embedding_batch_size_invalid"
    public_message = "The embedding batch size is outside the approved bounds."


class EmbeddingInputTooLongError(EmbeddingError):
    code = "embedding_input_too_long"
    public_message = "An embedding input exceeds the approved token limit."


class EmbeddingModelLoadError(EmbeddingError):
    code = "embedding_model_load_failed"
    public_message = "The approved local embedding model could not be loaded."


class EmbeddingExecutionError(EmbeddingError):
    code = "embedding_execution_failed"
    public_message = "The embedding model could not complete the operation."


class EmbeddingContractMismatchError(EmbeddingError):
    code = "embedding_contract_mismatch"
    public_message = "The embedding provider and vector collection are incompatible."


class EmbeddingProviderFailure(EmbeddingError):
    code = "embedding_provider_failure"
    public_message = "The embedding provider was instructed to fail."
