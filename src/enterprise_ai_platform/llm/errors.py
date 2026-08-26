"""Stable, redaction-safe language-model errors."""

from __future__ import annotations

from enum import StrEnum


class LLMErrorCode(StrEnum):
    """Public classifications that never contain provider response data."""

    INVALID_REQUEST = "llm_invalid_request"
    MALFORMED_RESPONSE = "llm_malformed_response"
    AUTHENTICATION = "llm_authentication_failed"
    AUTHORIZATION = "llm_authorization_failed"
    TIMEOUT = "llm_timeout"
    THROTTLED = "llm_throttled"
    UNAVAILABLE = "llm_unavailable"


class LLMError(Exception):
    """Base for normalized failures at the provider-neutral boundary."""

    code: LLMErrorCode
    public_message: str

    def __init__(self) -> None:
        super().__init__(self.public_message)


class LLMValidationError(LLMError):
    code = LLMErrorCode.INVALID_REQUEST
    public_message = "The language-model request is invalid."


class LLMMalformedResponseError(LLMError):
    code = LLMErrorCode.MALFORMED_RESPONSE
    public_message = "The language-model response is malformed."


class LLMAuthenticationError(LLMError):
    code = LLMErrorCode.AUTHENTICATION
    public_message = "Language-model authentication failed."


class LLMAuthorizationError(LLMError):
    code = LLMErrorCode.AUTHORIZATION
    public_message = "Language-model authorization failed."


class LLMTimeoutError(LLMError):
    code = LLMErrorCode.TIMEOUT
    public_message = "The language-model request timed out."


class LLMThrottlingError(LLMError):
    code = LLMErrorCode.THROTTLED
    public_message = "The language-model provider throttled the request."


class LLMUnavailableError(LLMError):
    code = LLMErrorCode.UNAVAILABLE
    public_message = "The language-model provider is unavailable."
