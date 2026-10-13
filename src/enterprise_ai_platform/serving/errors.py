"""Redaction-safe normalized errors for serving decisions and calls."""

from __future__ import annotations

from enum import StrEnum


class ServingErrorCode(StrEnum):
    INVALID_REQUEST = "serving_invalid_request"
    UNAPPROVED_ARTIFACT = "serving_unapproved_artifact"
    AUTHORIZATION = "serving_authorization_failed"
    TIMEOUT = "serving_timeout"
    THROTTLED = "serving_throttled"
    UNAVAILABLE = "serving_unavailable"
    MALFORMED_RESPONSE = "serving_malformed_response"


class ServingError(Exception):
    code: ServingErrorCode
    public_message: str

    def __init__(self) -> None:
        super().__init__(self.public_message)


class ServingValidationError(ServingError):
    code = ServingErrorCode.INVALID_REQUEST
    public_message = "The serving request is invalid."


class ServingAuthorizationError(ServingError):
    code = ServingErrorCode.AUTHORIZATION
    public_message = "The serving request is not authorized."


class ServingArtifactApprovalError(ServingError):
    code = ServingErrorCode.UNAPPROVED_ARTIFACT
    public_message = "The serving artifact is not approved."


class ServingTimeoutError(ServingError):
    code = ServingErrorCode.TIMEOUT
    public_message = "The serving request timed out."


class ServingUnavailableError(ServingError):
    code = ServingErrorCode.UNAVAILABLE
    public_message = "The serving provider is unavailable."
