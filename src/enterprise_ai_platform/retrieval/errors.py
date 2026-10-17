"""Stable errors returned by all vector-store implementations."""

from __future__ import annotations

from enum import StrEnum


class VectorStoreErrorCode(StrEnum):
    VALIDATION = "vector_store_validation"
    COLLECTION_MISMATCH = "vector_store_collection_mismatch"
    AUTHORIZATION_DENIED = "vector_store_authorization_denied"
    TIMEOUT = "vector_store_timeout"
    UNAVAILABLE = "vector_store_unavailable"


class VectorStoreError(Exception):
    """Base error with a non-sensitive stable code and message."""

    code = VectorStoreErrorCode.UNAVAILABLE
    retryable = False
    safe_message = "vector store operation failed"

    def __init__(self) -> None:
        super().__init__(self.safe_message)


class VectorStoreValidationError(VectorStoreError):
    code = VectorStoreErrorCode.VALIDATION
    safe_message = "vector store input is invalid"


class CollectionMismatchError(VectorStoreError):
    code = VectorStoreErrorCode.COLLECTION_MISMATCH
    safe_message = "vector collection does not match the approved specification"


class VectorStoreAuthorizationError(VectorStoreError):
    code = VectorStoreErrorCode.AUTHORIZATION_DENIED
    safe_message = "vector store operation is not authorized"


class VectorStoreTimeoutError(VectorStoreError):
    code = VectorStoreErrorCode.TIMEOUT
    retryable = True
    safe_message = "vector store operation timed out"


class VectorStoreUnavailableError(VectorStoreError):
    code = VectorStoreErrorCode.UNAVAILABLE
    retryable = True
    safe_message = "vector store is unavailable"


class RerankerErrorCode(StrEnum):
    """Stable, non-sensitive reranker failure classifications."""

    VALIDATION = "reranker_validation"
    INPUT_LIMIT = "reranker_input_limit"
    TIMEOUT = "reranker_timeout"
    UNAVAILABLE = "reranker_unavailable"
    SATURATED = "reranker_saturated"
    MALFORMED_RESPONSE = "reranker_malformed_response"


class RerankerError(Exception):
    """Base reranker error that never includes query or document content."""

    code = RerankerErrorCode.UNAVAILABLE
    retryable = False
    safe_message = "reranker operation failed"

    def __init__(self) -> None:
        super().__init__(self.safe_message)


class RerankerValidationError(RerankerError):
    code = RerankerErrorCode.VALIDATION
    safe_message = "reranker input is invalid"


class RerankerInputLimitError(RerankerError):
    code = RerankerErrorCode.INPUT_LIMIT
    safe_message = "reranker input exceeds the approved limit"


class RerankerTimeoutError(RerankerError):
    code = RerankerErrorCode.TIMEOUT
    safe_message = "reranker operation timed out"


class RerankerUnavailableError(RerankerError):
    code = RerankerErrorCode.UNAVAILABLE
    safe_message = "reranker is unavailable"


class RerankerSaturatedError(RerankerError):
    code = RerankerErrorCode.SATURATED
    safe_message = "reranker capacity is saturated"


class RerankerMalformedResponseError(RerankerError):
    code = RerankerErrorCode.MALFORMED_RESPONSE
    safe_message = "reranker response is invalid"
