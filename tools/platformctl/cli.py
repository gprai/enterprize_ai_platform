"""Offline, owner-gated lifecycle controls for the learning sandbox."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from . import __version__, bootstrap, deploy, plan, rollback
from .aws_inventory import AwsInventoryProvider, UnavailableAwsInventoryProvider
from .contracts import (
    Action,
    ApprovalError,
    ApprovalUsageRegistry,
    Clock,
    ContractError,
    MutationRequest,
    SystemClock,
    UnavailableApprovalUsageRegistry,
    load_approval_record,
    validate_aws_account_id,
    validate_aws_region,
    validate_runtime_token,
    validate_sha256,
)
from .destroy import DestroyMode, action_for_mode
from .destroy import validate_request as validate_destroy_request
from .validate import (
    EXPECTED_FEATURE,
    EXPECTED_FEATURES,
    EXPECTED_PROJECT,
    EXPECTED_SCHEMA_VERSION,
    PERMITTED_STATUSES,
    REQUIRED_DIRECTORIES,
    REQUIRED_FILES,
    MatrixValidationError,
    load_feature_matrix,
    repository_root,
    validate_feature_matrix,
    validate_repository,
)
from .verify_clean import verify_clean

__all__ = [
    "EXPECTED_FEATURE",
    "EXPECTED_FEATURES",
    "EXPECTED_PROJECT",
    "EXPECTED_SCHEMA_VERSION",
    "PERMITTED_STATUSES",
    "REQUIRED_DIRECTORIES",
    "REQUIRED_FILES",
    "MatrixValidationError",
    "build_parser",
    "load_feature_matrix",
    "main",
    "repository_root",
    "validate_feature_matrix",
    "validate_repository",
]


def _runtime_token(field_name: str) -> Callable[[str], str]:
    def parse(value: str) -> str:
        try:
            return validate_runtime_token(value, field_name)
        except ContractError as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc

    return parse


def _sha256(value: str) -> str:
    try:
        return validate_sha256(value)
    except ContractError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _account_id(value: str) -> str:
    try:
        return validate_aws_account_id(value)
    except ContractError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _region(value: str) -> str:
    try:
        return validate_aws_region(value)
    except ContractError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _add_mutation_arguments(
    parser: argparse.ArgumentParser, *, require_resource_expiry: bool
) -> None:
    parser.add_argument("--environment", required=True, type=_runtime_token("environment"))
    parser.add_argument("--aws-account-id", required=True, type=_account_id)
    parser.add_argument("--aws-region", required=True, type=_region)
    parser.add_argument("--target", required=True, type=_runtime_token("target"))
    parser.add_argument("--artifact-sha256", required=True, type=_sha256)
    parser.add_argument("--approval-record", required=True, type=Path)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--executor", required=True, type=_runtime_token("executor"))
    if require_resource_expiry:
        parser.add_argument("--resource-expires-at", required=True)


def build_parser() -> argparse.ArgumentParser:
    """Build the exact W1-004 offline command contract."""
    parser = argparse.ArgumentParser(
        prog="platformctl",
        description="Offline owner-gated enterprise AI platform lifecycle controls.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subcommands = parser.add_subparsers(dest="command")

    bootstrap_parser = subcommands.add_parser(
        "bootstrap", help="validate an approved bootstrap intent without executing it"
    )
    _add_mutation_arguments(bootstrap_parser, require_resource_expiry=True)

    plan_parser = subcommands.add_parser(
        "plan", help="validate planning intent without running Terraform"
    )
    plan_parser.add_argument("--environment", required=True, type=_runtime_token("environment"))
    plan_parser.add_argument("--target", required=True, type=_runtime_token("target"))

    deploy_parser = subcommands.add_parser(
        "deploy", help="validate an approved deployment intent without executing it"
    )
    _add_mutation_arguments(deploy_parser, require_resource_expiry=True)

    subcommands.add_parser("validate", help="validate the approved repository contract read-only")

    rollback_parser = subcommands.add_parser(
        "rollback", help="validate an approved immutable rollback intent"
    )
    _add_mutation_arguments(rollback_parser, require_resource_expiry=False)

    destroy_parser = subcommands.add_parser(
        "destroy", help="validate destroy-safe or sandbox purge intent"
    )
    destroy_parser.add_argument(
        "--mode", required=True, choices=[mode.value for mode in DestroyMode]
    )
    _add_mutation_arguments(destroy_parser, require_resource_expiry=False)

    clean_parser = subcommands.add_parser(
        "verify-clean", help="classify injected tag and service inventory"
    )
    clean_parser.add_argument("--environment", required=True, type=_runtime_token("environment"))

    return parser


def _mutation_request(arguments: argparse.Namespace, action: Action) -> MutationRequest:
    return MutationRequest(
        action=action,
        environment=cast(str, arguments.environment),
        aws_account_id=cast(str, arguments.aws_account_id),
        aws_region=cast(str, arguments.aws_region),
        target=cast(str, arguments.target),
        artifact_sha256=cast(str, arguments.artifact_sha256),
        confirmation=cast(str, arguments.confirmation),
        executor=cast(str, arguments.executor),
        resource_expires_at=cast(str | None, getattr(arguments, "resource_expires_at", None)),
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    clock: Clock | None = None,
    usage_registry: ApprovalUsageRegistry | None = None,
    inventory_provider: AwsInventoryProvider | None = None,
) -> int:
    """Validate one offline lifecycle intent without performing a mutation."""
    parser = build_parser()
    arguments = parser.parse_args(argv)

    if arguments.command is None:
        parser.print_help()
        return 0

    effective_clock = clock or SystemClock()
    effective_usage = usage_registry or UnavailableApprovalUsageRegistry()
    effective_inventory = inventory_provider or UnavailableAwsInventoryProvider()

    try:
        if arguments.command == "validate":
            errors = validate_repository()
            if errors:
                for error in errors:
                    print(f"ERROR: {error}", file=sys.stderr)
                return 1
            print("CODE-STAGE VALIDATION PASS: approved repository contract is present")
            return 0

        if arguments.command == "plan":
            result = plan.validate_request(arguments.environment, arguments.target)
        elif arguments.command == "verify-clean":
            result = verify_clean(
                effective_inventory,
                cast(str, arguments.environment),
                effective_clock.now(),
            )
        else:
            approval = load_approval_record(cast(Path, arguments.approval_record))
            if arguments.command == "bootstrap":
                request = _mutation_request(arguments, Action.BOOTSTRAP)
                result = bootstrap.validate_request(
                    request, approval, effective_usage, effective_clock.now()
                )
            elif arguments.command == "deploy":
                request = _mutation_request(arguments, Action.DEPLOY)
                result = deploy.validate_request(
                    request, approval, effective_usage, effective_clock.now()
                )
            elif arguments.command == "rollback":
                request = _mutation_request(arguments, Action.ROLLBACK)
                result = rollback.validate_request(
                    request, approval, effective_usage, effective_clock.now()
                )
            elif arguments.command == "destroy":
                mode = DestroyMode(cast(str, arguments.mode))
                request = _mutation_request(arguments, action_for_mode(mode))
                result = validate_destroy_request(
                    mode,
                    request,
                    approval,
                    effective_usage,
                    effective_clock.now(),
                )
            else:
                raise ContractError("unsupported command")
    except ApprovalError as exc:
        print(f"APPROVAL ERROR: {exc}", file=sys.stderr)
        return 4
    except ContractError as exc:
        print(f"VALIDATION ERROR: {exc}", file=sys.stderr)
        return 1

    output = sys.stdout if result.exit_code == 0 else sys.stderr
    print(result.message, file=output)
    return int(result.exit_code)
