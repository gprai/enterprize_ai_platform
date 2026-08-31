"""Contract tests for the exact W1-004 CLI and inventory surface."""

from __future__ import annotations

import argparse

import pytest
from tools.platformctl.aws_inventory import ServiceIdentifier
from tools.platformctl.cli import build_parser
from tools.platformctl.contracts import (
    REQUIRED_APPROVAL_FIELDS,
    Action,
    ExitCode,
)


def test_cli_exposes_exact_approved_commands() -> None:
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert set(subparsers.choices) == {
        "bootstrap",
        "plan",
        "deploy",
        "validate",
        "rollback",
        "destroy",
        "verify-clean",
    }


def test_cli_has_no_operational_execute_switch() -> None:
    assert "--execute" not in build_parser().format_help()


def test_approval_contract_has_exact_fields_and_actions() -> None:
    assert REQUIRED_APPROVAL_FIELDS == {
        "schema_version",
        "approval_id",
        "action",
        "environment",
        "aws_account_id",
        "aws_region",
        "target",
        "artifact_sha256",
        "approver",
        "approved_at",
        "expires_at",
    }
    assert [action.value for action in Action] == [
        "BOOTSTRAP",
        "DEPLOY",
        "ROLLBACK",
        "DESTROY-SAFE",
        "PURGE-SANDBOX",
    ]


def test_exit_codes_are_stable() -> None:
    assert {member.name: member.value for member in ExitCode} == {
        "SUCCESS": 0,
        "VALIDATION_FAILURE": 1,
        "USAGE_ERROR": 2,
        "PROVIDER_UNAVAILABLE": 3,
        "APPROVAL_FAILURE": 4,
    }


def test_inventory_contract_covers_every_approved_service() -> None:
    assert [service.value for service in ServiceIdentifier] == [
        "EKS",
        "ELB",
        "EBS",
        "ENI",
        "EIP",
        "OpenSearch",
        "S3",
        "ECR",
        "CloudWatch Logs",
        "Secrets Manager",
        "KMS",
        "IAM",
        "Lambda",
        "Glue",
        "Step Functions",
        "EventBridge",
    ]


def test_malformed_cli_input_uses_argparse_exit_two() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["plan", "--environment", "TODO_USER", "--target", "x"])
    assert exc_info.value.code == 2
