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
