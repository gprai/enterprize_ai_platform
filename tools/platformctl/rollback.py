"""Owner-gated infrastructure rollback validation."""

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
    """Validate an infrastructure rollback without redefining release rollback."""
    if request.action is not Action.INFRASTRUCTURE_ROLLBACK:
        raise ContractError("rollback request uses the wrong action")
    validate_mutation_request(
        request,
        approval,
        usage_registry,
        now,
    )
    return OperationResult(
        ExitCode.SUCCESS,
        "DRY_RUN: infrastructure rollback intent validated; no plan was applied",
    )


def apply_approved_infrastructure_rollback(
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
    """Apply a separately reviewed last-known-good Terraform plan."""
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


def validate_w6_004_known_good_identity(
    *, current_digest: str, regression_digest: str, known_good_digest: str
) -> None:
    """Require a distinct regression and exact immutable rollback target."""

    from .image_lifecycle import DIGEST, ImageLifecycleError

    values = (current_digest, regression_digest, known_good_digest)
    if any(DIGEST.fullmatch(value) is None for value in values):
        raise ImageLifecycleError("rollback identities must be immutable digests")
    if current_digest != known_good_digest or regression_digest == known_good_digest:
        raise ImageLifecycleError("known-good and safe-regression identities differ incorrectly")
