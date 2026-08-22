"""Offline destroy-safe and purge-sandbox validation."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

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


class DestroyMode(StrEnum):
    """Approved destruction behaviors with different safety semantics."""

    DESTROY_SAFE = "destroy-safe"
    PURGE_SANDBOX = "purge-sandbox"


def action_for_mode(mode: DestroyMode) -> Action:
    """Map a CLI mode to its separately approved action value."""
    if mode is DestroyMode.DESTROY_SAFE:
        return Action.DESTROY_SAFE
    return Action.PURGE_SANDBOX


def validate_request(
    mode: DestroyMode,
    request: MutationRequest,
    approval: ApprovalRecord,
    usage_registry: ApprovalUsageRegistry,
    now: datetime,
) -> OperationResult:
    """Validate destruction intent without deleting any resource."""
    expected_action = action_for_mode(mode)
    if request.action is not expected_action:
        raise ContractError("destroy request action does not match its mode")
    if mode is DestroyMode.PURGE_SANDBOX and request.environment != "sandbox":
        raise ContractError("purge-sandbox is permitted only for sandbox")
    validate_mutation_request(
        request,
        approval,
        usage_registry,
        now,
        require_resource_expiry=False,
    )
    return OperationResult(
        ExitCode.SUCCESS,
        f"DRY_RUN: {mode.value} intent validated; no teardown executed",
    )

