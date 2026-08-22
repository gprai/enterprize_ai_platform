"""Offline immutable-release rollback validation."""

from __future__ import annotations

from datetime import datetime

from .contracts import (
    Action,
    ApprovalRecord,
    ApprovalUsageRegistry,
    ContractError,
    ExitCode,
    MutationRequest,
    OperationResult,
    validate_mutation_request,
)


def validate_request(
    request: MutationRequest,
    approval: ApprovalRecord,
    usage_registry: ApprovalUsageRegistry,
    now: datetime,
) -> OperationResult:
    """Validate an immutable rollback request without restoring a release."""
    if request.action is not Action.ROLLBACK:
        raise ContractError("rollback request uses the wrong action")
    validate_mutation_request(
        request,
        approval,
        usage_registry,
        now,
        require_resource_expiry=False,
    )
    return OperationResult(
        ExitCode.SUCCESS,
        "DRY_RUN: rollback intent validated; no release was restored",
    )

