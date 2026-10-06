"""Offline deployment-intent validation."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .contracts import (
    Action,
    ApprovalConsumptionRegistry,
    ApprovalRecord,
    ApprovalUsageRegistry,
    ContractError,
    ExitCode,
    MutationRequest,
    OperationResult,
    VerifiedExecutionContext,
    validate_mutation_request,
)
from .terraform_runner import TerraformRunner


def validate_request(
    request: MutationRequest,
    approval: ApprovalRecord,
    usage_registry: ApprovalUsageRegistry,
    now: datetime,
) -> OperationResult:
    """Validate a separately approved deployment without executing it."""
    if request.action is not Action.PLATFORM_APPLY:
        raise ContractError("deploy request uses the wrong action")
    validate_mutation_request(
        request,
        approval,
        usage_registry,
        now,
    )
    return OperationResult(
        ExitCode.SUCCESS,
        "DRY_RUN: exact platform plan apply intent validated; no deployment executed",
    )


def apply_approved_platform_plan(
    request: MutationRequest,
    approval: ApprovalRecord,
    usage_registry: ApprovalConsumptionRegistry,
    now: datetime,
    *,
    runner: TerraformRunner,
    terraform_root: Path,
    saved_plan: Path,
    execution_context: VerifiedExecutionContext | None = None,
) -> OperationResult:
    """Apply only the reviewed platform plan; never create a replacement plan."""
    validate_request(request, approval, usage_registry, now)
    from .plan import execute_reviewed_plan

    return execute_reviewed_plan(
        request,
        approval.approval_id,
        usage_registry,
        now,
        runner=runner,
        terraform_root=terraform_root,
        saved_plan=saved_plan,
        execution_context=execution_context,
    )


def validate_w6_004_stage_order(stages: tuple[str, ...]) -> None:
    """Validate complete lifecycle ordering without executing any stage."""

    from .live_validation import validate_stage_sequence

    validate_stage_sequence(stages)
