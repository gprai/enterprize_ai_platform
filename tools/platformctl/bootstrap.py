"""Offline bootstrap-intent validation."""

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
    """Validate a separately approved bootstrap request without executing it."""
    if request.action is not Action.BOOTSTRAP:
        raise ContractError("bootstrap request uses the wrong action")
    validate_mutation_request(
        request,
        approval,
        usage_registry,
        now,
        require_resource_expiry=True,
    )
    return OperationResult(
        ExitCode.SUCCESS,
        "DRY_RUN: bootstrap intent validated; no Terraform or AWS action executed",
    )

