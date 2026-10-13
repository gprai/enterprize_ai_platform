"""Stable, content-free failures for the asynchronous orchestration boundary."""

from __future__ import annotations

from enum import StrEnum


class OrchestrationErrorCode(StrEnum):
    INVALID_REQUEST = "orchestration_invalid_request"
    AUTHORIZATION = "orchestration_authorization_failed"
    IDEMPOTENCY_CONFLICT = "orchestration_idempotency_conflict"
    QUOTA_EXCEEDED = "orchestration_quota_exceeded"
    APPROVAL = "orchestration_approval_failed"
    STATE_CONFLICT = "orchestration_state_conflict"
    DEADLINE = "orchestration_deadline_exceeded"
    PROVIDER = "orchestration_provider_not_approved"
    RESUME = "orchestration_resume_rejected"


class OrchestrationError(Exception):
    code: OrchestrationErrorCode
    safe_message: str

    def __init__(self) -> None:
        super().__init__(self.safe_message)


class OrchestrationValidationError(OrchestrationError):
    code = OrchestrationErrorCode.INVALID_REQUEST
    safe_message = "The workflow request is invalid."


class OrchestrationAuthorizationError(OrchestrationError):
    code = OrchestrationErrorCode.AUTHORIZATION
    safe_message = "The workflow request is not authorized."


class OrchestrationIdempotencyError(OrchestrationError):
    code = OrchestrationErrorCode.IDEMPOTENCY_CONFLICT
    safe_message = "The workflow idempotency identity conflicts with prior work."


class OrchestrationQuotaError(OrchestrationError):
    code = OrchestrationErrorCode.QUOTA_EXCEEDED
    safe_message = "The workflow tenant is at its approved capacity."


class OrchestrationApprovalError(OrchestrationError):
    code = OrchestrationErrorCode.APPROVAL
    safe_message = "The workflow approval is invalid or unavailable."


class OrchestrationStateConflictError(OrchestrationError):
    code = OrchestrationErrorCode.STATE_CONFLICT
    safe_message = "The workflow state changed before the requested transition."


class OrchestrationDeadlineError(OrchestrationError):
    code = OrchestrationErrorCode.DEADLINE
    safe_message = "The workflow deadline was exceeded."


class OrchestrationProviderError(OrchestrationError):
    code = OrchestrationErrorCode.PROVIDER
    safe_message = "The workflow model or provider is not approved."


class OrchestrationResumeError(OrchestrationError):
    code = OrchestrationErrorCode.RESUME
    safe_message = "The workflow cannot be resumed with the supplied identity."
