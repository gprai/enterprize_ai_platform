"""Offline plan-intent validation."""

from __future__ import annotations

from .contracts import ExitCode, OperationResult, validate_runtime_token


def validate_request(environment: str, target: str) -> OperationResult:
    """Validate a read-only planning request without running Terraform."""
    validate_runtime_token(environment, "environment")
    validate_runtime_token(target, "target")
    return OperationResult(
        ExitCode.SUCCESS,
        "DRY_RUN: plan intent validated; Terraform plan was NOT RUN",
    )

