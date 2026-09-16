"""Offline bootstrap-intent validation."""

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
    """Validate a separately approved bootstrap request without executing it."""
    if request.action is not Action.BOOTSTRAP_APPLY:
        raise ContractError("bootstrap request uses the wrong action")
    validate_mutation_request(
        request,
        approval,
        usage_registry,
        now,
    )
    return OperationResult(
        ExitCode.SUCCESS,
        "DRY_RUN: bootstrap intent validated; no Terraform or AWS action executed",
    )


def apply_approved_bootstrap_plan(
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
    """Apply only exact bootstrap plan bytes after all approval gates pass."""
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
