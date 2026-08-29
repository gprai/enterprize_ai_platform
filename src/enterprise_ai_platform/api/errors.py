"""Stable content-free API errors and domain-to-HTTP normalization."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from enterprise_ai_platform.agent.errors import (
    AgentApprovalConflictError,
    AgentAuthorizationError,
    AgentDeadlineError,
    AgentError,
    AgentNotConfiguredError,
    AgentOverloadedError,
    AgentStateUnavailableError,
)
from enterprise_ai_platform.embeddings.errors import (
    EmbeddingBatchSizeError,
    EmbeddingError,
    EmbeddingInputError,
    EmbeddingInputTooLongError,
)
from enterprise_ai_platform.guardrails.errors import GuardrailInputError
from enterprise_ai_platform.llm.errors import (
    LLMAuthenticationError,
    LLMAuthorizationError,
    LLMError,
    LLMMalformedResponseError,
    LLMThrottlingError,
    LLMTimeoutError,
    LLMUnavailableError,
    LLMValidationError,
)
from enterprise_ai_platform.rag.errors import (
    RAGConfigurationError,
    RAGError,
    RAGOutputValidationError,
)
from enterprise_ai_platform.retrieval.errors import (
    CollectionMismatchError,
    VectorStoreAuthorizationError,
    VectorStoreError,
    VectorStoreTimeoutError,
    VectorStoreUnavailableError,
    VectorStoreValidationError,
)

SAFE_MESSAGES: Final[dict[str, str]] = {
    "api_unsupported_media_type": "The request media type is unsupported.",
    "api_request_too_large": "The request body is too large.",
    "api_request_malformed": "The request body is malformed.",
    "api_request_invalid": "The request body is invalid.",
    "authentication_not_configured": "Authentication is not configured.",
    "authentication_required": "Authentication is required.",
    "authentication_invalid": "Authentication is invalid.",
    "authorization_denied": "The operation is not authorized.",
    "api_query_deadline_exceeded": "The query deadline was exceeded.",
    "api_overloaded": "The query service is at capacity.",
    "service_not_ready": "The service is not ready.",
    "agent_disabled": "The agent endpoint is disabled.",
    "agent_not_configured": "The agent controller is not configured.",
    "agent_approval_conflict": "The approval conflicts with the current state.",
    "agent_deadline_exceeded": "The agent deadline was exceeded.",
    "agent_overloaded": "The agent service is at capacity.",
    "agent_state_unavailable": "The agent state is unavailable.",
    "api_not_found": "The requested resource was not found.",
    "api_method_not_allowed": "The request method is not allowed.",
    "internal_error": "The request could not be completed.",
}


class APIError(Exception):
    """One normalized failure containing only approved public fields."""

    def __init__(
        self,
        *,
        status_code: int,
        code: str,
        message: str,
        retryable: bool | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.public_message = message
        self.retryable = retryable
        self.headers = dict(headers or {})


def api_error(
    status_code: int,
    code: str,
    *,
    retryable: bool | None = None,
    headers: Mapping[str, str] | None = None,
) -> APIError:
    """Build one policy-defined API failure without raw exception content."""

    return APIError(
        status_code=status_code,
        code=code,
        message=SAFE_MESSAGES[code],
        retryable=retryable,
        headers=headers,
    )


class AuthenticationNotConfiguredError(APIError):
    def __init__(self) -> None:
        error = api_error(503, "authentication_not_configured")
        super().__init__(
            status_code=error.status_code,
            code=error.code,
            message=error.public_message,
        )


class AuthenticationRequiredError(APIError):
    def __init__(self) -> None:
        error = api_error(401, "authentication_required")
        super().__init__(
            status_code=error.status_code,
            code=error.code,
            message=error.public_message,
        )


class AuthenticationInvalidError(APIError):
    def __init__(self) -> None:
        error = api_error(401, "authentication_invalid")
        super().__init__(
            status_code=error.status_code,
            code=error.code,
            message=error.public_message,
        )


class AuthorizationDeniedError(APIError):
    def __init__(self) -> None:
        error = api_error(403, "authorization_denied")
        super().__init__(
            status_code=error.status_code,
            code=error.code,
            message=error.public_message,
        )


def _domain_error(
    status_code: int,
    error: object,
    *,
    retryable: bool | None = None,
) -> APIError:
    raw_code = getattr(error, "code", None)
    message = getattr(error, "safe_message", None) or getattr(
        error,
        "public_message",
        None,
    )
    if not isinstance(raw_code, str) or not isinstance(message, str):
        return api_error(500, "internal_error")
    return APIError(
        status_code=status_code,
        code=str(raw_code),
        message=message,
        retryable=retryable,
    )


def normalize_domain_error(error: Exception) -> APIError:
    """Map an approved lower-layer error without exposing its raw text."""

    if isinstance(error, GuardrailInputError):
        return _domain_error(422, error)
    if isinstance(error, VectorStoreAuthorizationError):
        return _domain_error(403, error, retryable=error.retryable)
    if isinstance(error, VectorStoreTimeoutError):
        return _domain_error(504, error, retryable=error.retryable)
    if isinstance(error, VectorStoreUnavailableError):
        return _domain_error(503, error, retryable=error.retryable)
    if isinstance(error, (VectorStoreValidationError, CollectionMismatchError)):
        return _domain_error(503, error, retryable=error.retryable)
    if isinstance(error, VectorStoreError):
        return _domain_error(503, error, retryable=error.retryable)
    if isinstance(
        error,
        (EmbeddingInputError, EmbeddingBatchSizeError, EmbeddingInputTooLongError),
    ):
        return _domain_error(422, error)
    if isinstance(error, EmbeddingError):
        return _domain_error(503, error)
    if isinstance(error, RAGConfigurationError):
        return _domain_error(503, error)
    if isinstance(error, RAGOutputValidationError):
        return _domain_error(502, error)
    if isinstance(error, RAGError):
        return _domain_error(502, error)
    if isinstance(error, (LLMValidationError, LLMMalformedResponseError)):
        return _domain_error(502, error)
    if isinstance(error, (LLMAuthenticationError, LLMAuthorizationError)):
        return _domain_error(503, error)
    if isinstance(error, LLMTimeoutError):
        return _domain_error(504, error)
    if isinstance(error, (LLMThrottlingError, LLMUnavailableError)):
        return _domain_error(503, error)
    if isinstance(error, LLMError):
        return _domain_error(503, error)
    return api_error(500, "internal_error")


def normalize_agent_error(error: AgentError) -> APIError:
    """Map only the approved content-free W4-002 failures."""

    if isinstance(error, AgentNotConfiguredError):
        return api_error(503, "agent_not_configured")
    if isinstance(error, AgentAuthorizationError):
        return api_error(403, "authorization_denied")
    if isinstance(error, AgentApprovalConflictError):
        return api_error(409, "agent_approval_conflict")
    if isinstance(error, AgentDeadlineError):
        return api_error(504, "agent_deadline_exceeded")
    if isinstance(error, AgentOverloadedError):
        return api_error(
            503,
            "agent_overloaded",
            retryable=True,
            headers={"Retry-After": "1"},
        )
    if isinstance(error, AgentStateUnavailableError):
        return api_error(503, "agent_state_unavailable")
    return api_error(500, "internal_error")
