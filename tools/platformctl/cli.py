"""Offline, owner-gated lifecycle controls for the learning sandbox."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from pathlib import Path
from string import ascii_uppercase, digits
from typing import Protocol, cast

from . import __version__, bootstrap, deploy, plan, plan_artifact_producer, rollback
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
from .lifecycle_io import (
    BoundEvidenceReader,
    bounded_relative_path,
    decode_json_strict,
    decode_operational_record,
    ensure_external_path,
    load_lifecycle_config,
    sha256_bytes,
)
from .lifecycle_models import (
    DIAGNOSTIC_SCHEMA_VERSION,
    ApprovalRecordV2,
    MutationEnvelope,
    ReviewPackage,
    W12RuntimeProofRoots,
)
from .live_validation import (
    SCHEMA_FIELDS,
    W6004Error,
    load_strict_json,
    validate_evidence_record,
    validate_runtime_bindings,
    validate_source_contract,
)
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


def _add_mutation_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--environment", required=True, type=_runtime_token("environment"))
    parser.add_argument("--aws-account-id", required=True, type=_account_id)
    parser.add_argument("--aws-region", required=True, type=_region)
    parser.add_argument("--target", required=True, type=_runtime_token("target"))
    parser.add_argument("--artifact-sha256", required=True, type=_sha256)
    parser.add_argument("--approval-record", required=True, type=Path)
    parser.add_argument("--confirmation", required=True)
    parser.add_argument("--executor", required=True, type=_runtime_token("executor"))


def _add_execution_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--execute", action="store_true", help="explicit separately authorized execution"
    )
    parser.add_argument("--request-file", type=Path, help="bounded v2 owner request")
    parser.add_argument("--request-sha256", type=_sha256, help="exact owner-approved request hash")
    parser.add_argument(
        "--runtime-file", type=Path, help="external production adapter configuration"
    )
    parser.add_argument("--runtime-sha256", type=_sha256, help="exact runtime configuration hash")


def _add_plan_artifact_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--owner-input-file", required=True, type=Path)
    parser.add_argument("--owner-input-sha256", required=True, type=_sha256)
    parser.add_argument("--operation-root", required=True, type=Path)


def _add_plan_owner_envelope_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--owner-confirmation-file", required=True, type=Path)
    parser.add_argument("--owner-confirmation-sha256", required=True, type=_sha256)
    parser.add_argument("--state-evidence-file", required=True, type=Path)
    parser.add_argument("--state-evidence-sha256", required=True, type=_sha256)
    parser.add_argument("--variables-example-file", required=True, type=Path)
    parser.add_argument("--variables-example-sha256", required=True, type=_sha256)
    parser.add_argument("--backend-example-file", required=True, type=Path)
    parser.add_argument("--backend-example-sha256", required=True, type=_sha256)
    parser.add_argument("--operation-root", required=True, type=Path)


class LifecycleExecutionServices(Protocol):
    """The repository coordinator owns execution; launchers supply no lifecycle logic."""

    external_root: Path
    repository_root: Path

    def execute_request(
        self,
        command: str,
        payload: bytes,
        proof_roots: W12RuntimeProofRoots | None = None,
    ) -> tuple[int, str]:
        """Execute only the bound command through the shared coordinator and gate."""
        ...


def _validate_cli_mutation_binding(
    arguments: argparse.Namespace,
    payload: bytes,
    external: Path,
    repository: Path,
) -> None:
    if not hasattr(arguments, "artifact_sha256"):
        value = decode_json_strict(payload)
        if not isinstance(value, dict):
            raise ContractError("CLI_REQUEST_OBJECT_REQUIRED")
        if "request" in value:
            nested = value["request"]
            if not isinstance(nested, dict) or (
                nested.get("environment") != arguments.environment
                or nested.get("target") != getattr(arguments, "target", None)
            ):
                raise ContractError("CLI_REQUEST_SCOPE_MISMATCH")
        if "review_path" in value:
            root_value = value.get("operation_root")
            review_path = value.get("review_path")
            review_hash = value.get("review_sha256")
            if not all(
                isinstance(item, str)
                for item in (
                    root_value,
                    review_path,
                    review_hash,
                )
            ):
                raise ContractError("CLI_REVIEW_BINDING_REQUIRED")
            root = ensure_external_path(Path(cast(str, root_value)), external, repository)
            relative = bounded_relative_path(cast(str, review_path))
            reader = BoundEvidenceReader(root, repository)
            package = decode_operational_record(
                reader.read(
                    relative,
                    cast(str, review_hash),
                    (root / relative).stat().st_size,
                ),
                ReviewPackage,
            )
            if package.environment != arguments.environment or (
                hasattr(arguments, "target") and package.target != arguments.target
            ):
                raise ContractError("CLI_REVIEW_SCOPE_MISMATCH")
        return
    envelope = decode_operational_record(payload, MutationEnvelope)
    root = ensure_external_path(Path(envelope.operation_root), external, repository)
    reader = BoundEvidenceReader(root, repository)
    package = decode_operational_record(
        reader.read(
            envelope.review_path,
            envelope.review_sha256,
            (root / bounded_relative_path(envelope.review_path)).stat().st_size,
        ),
        ReviewPackage,
    )
    approval = decode_operational_record(
        reader.read(
            envelope.approval_path,
            envelope.approval_sha256,
            (root / bounded_relative_path(envelope.approval_path)).stat().st_size,
        ),
        ApprovalRecordV2,
    )
    if (
        arguments.environment != package.environment
        or arguments.target != package.target
        or arguments.aws_account_id != package.account_id
        or arguments.aws_region != package.region
        or arguments.artifact_sha256 != package.artifact.sha256
        or arguments.executor != approval.executor
        or arguments.confirmation != approval.confirmation
        or ensure_external_path(arguments.approval_record, external, repository)
        != root / envelope.approval_path
    ):
        raise ApprovalError("CLI_MUTATION_REVIEW_MISMATCH")


def build_parser() -> argparse.ArgumentParser:
    """Build the exact W5-004 owner-gated lifecycle command contract."""
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

    subcommands.add_parser("validate", help="validate the approved repository contract read-only")
    w6_004_source = subcommands.add_parser(
        "w6-004-validate-source",
        help="validate the inert W6-004 source contract without AWS or mutation",
    )
    w6_004_source.add_argument(
        "--config",
        type=Path,
        default=Path("configs/lifecycle/w6-004.json"),
    )
    w6_004_evidence = subcommands.add_parser(
        "w6-004-validate-evidence",
        help="validate one closed W6-004 evidence record without mutation",
    )
    w6_004_evidence.add_argument("--evidence", type=Path, required=True)
    w6_004_evidence.add_argument("--schema", choices=sorted(SCHEMA_FIELDS), required=True)
    w6_004_evidence.add_argument("--consumed-approval", action="append", default=[])
    w6_004_runtime = subcommands.add_parser(
        "w6-004-validate-runtime",
        help="validate owner-bound W6-004 runtime inputs without AWS or mutation",
    )
    w6_004_runtime.add_argument("--bindings", type=Path, required=True)
    envelope_parser = subcommands.add_parser(
        "prepare-plan-owner-envelope",
        help="construct fresh typed owner inputs without Terraform, AWS, or network access",
    )
    _add_plan_owner_envelope_arguments(envelope_parser)
    producer_parser = subcommands.add_parser(
        "prepare-plan-artifacts",
        help="validate explicit owner inputs and write fresh request/runtime JSON only",
    )
    _add_plan_artifact_arguments(producer_parser)

    for command, description in (
        ("bootstrap-plan", "prepare a separately reviewed bootstrap saved plan"),
        ("platform-plan", "prepare a separately reviewed platform saved plan"),
        ("policy-review", "evaluate normalized real-plan JSON with approved policy"),
        ("cost-review", "evaluate the plan against the USD 3 lifecycle ceiling"),
        ("aws-verify", "verify exact AWS account, Region, and caller identity"),
        ("destroy-plan", "prepare a separately reviewed platform destroy plan"),
    ):
        command_parser = subcommands.add_parser(command, help=description)
        command_parser.add_argument(
            "--environment", required=True, type=_runtime_token("environment")
        )
        command_parser.add_argument("--target", required=True, type=_runtime_token("target"))
        _add_execution_arguments(command_parser)
        if command in {"policy-review", "destroy-plan"}:
            command_parser.add_argument(
                "--w12-retention-proof-root", type=Path, action="append", default=[]
            )
        if command == "aws-verify":
            command_parser.add_argument("--diagnostic", action="store_true")
            command_parser.add_argument("--prepare-diagnostic", action="store_true")
            command_parser.add_argument("--source-sha256", type=_sha256)
            command_parser.add_argument("--resolution", action="store_true")
            command_parser.add_argument("--resolution-followup", action="store_true")
            command_parser.add_argument("--prerequisite-resolution", action="store_true")
            command_parser.add_argument("--prerequisite-correction", action="store_true")
            command_parser.add_argument("--prepare-prerequisite-correction", action="store_true")
            command_parser.add_argument("--owner-approval-file")
            command_parser.add_argument("--owner-approval-sha256", type=_sha256)
            command_parser.add_argument("--charging-evidence-file")
            command_parser.add_argument("--charging-evidence-sha256", type=_sha256)
            command_parser.add_argument("--evidence-identity-sha256", type=_sha256)
            command_parser.add_argument("--evidence-sha256", type=_sha256)

    for command, description in (
        ("bootstrap-apply", "apply only exact approved bootstrap plan bytes"),
        ("platform-apply", "apply only exact approved platform plan bytes"),
        (
            "infrastructure-rollback",
            "apply a separately reviewed last-known-good infrastructure plan",
        ),
        ("purge-sandbox", "purge only separately approved sandbox residue"),
        ("platform-destroy", "apply only exact approved platform destroy-plan bytes"),
        ("bootstrap-destroy", "destroy bootstrap only after platform cleanliness proof"),
    ):
        command_parser = subcommands.add_parser(command, help=description)
        _add_mutation_arguments(command_parser)
        _add_execution_arguments(command_parser)
        if command in {"purge-sandbox", "platform-destroy"}:
            command_parser.add_argument(
                "--w12-retention-proof-root", type=Path, action="append", default=[]
            )

    clean_parser = subcommands.add_parser(
        "verify-clean", help="classify injected tag and service inventory"
    )
    clean_parser.add_argument("--environment", required=True, type=_runtime_token("environment"))
    _add_execution_arguments(clean_parser)
    clean_parser.add_argument("--w12-retention-proof-root", type=Path, action="append", default=[])

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
    )


def main(
    argv: Sequence[str] | None = None,
    *,
    clock: Clock | None = None,
    usage_registry: ApprovalUsageRegistry | None = None,
    inventory_provider: AwsInventoryProvider | None = None,
    execution_services: LifecycleExecutionServices | None = None,
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
        if arguments.command == "w6-004-validate-source":
            try:
                print(validate_source_contract(arguments.config))
            except W6004Error as exc:
                print(f"W6-004 SOURCE VALIDATION FAILED: {exc}", file=sys.stderr)
                return 1
            return 0
        if arguments.command == "w6-004-validate-evidence":
            try:
                value = load_strict_json(arguments.evidence)
                validated = validate_evidence_record(
                    value,
                    expected_schema=arguments.schema,
                    consumed_approvals=tuple(arguments.consumed_approval),
                )
            except W6004Error as exc:
                print(f"W6-004 EVIDENCE VALIDATION FAILED: {exc}", file=sys.stderr)
                return 1
            print(f"W6-004 EVIDENCE VALID: {validated['schema_version']}")
            return 0
        if arguments.command == "w6-004-validate-runtime":
            try:
                validate_runtime_bindings(load_strict_json(arguments.bindings))
            except W6004Error as exc:
                print(f"W6-004 RUNTIME VALIDATION FAILED: {exc}", file=sys.stderr)
                return 1
            print("W6-004 OWNER RUNTIME BINDINGS VALID - NO MUTATION EXECUTED")
            return 0
        if arguments.command == "prepare-plan-owner-envelope":
            repository = repository_root()
            configuration = load_lifecycle_config(repository / "configs/lifecycle/w5-004.json")
            paths = cast(dict[str, str], configuration["external_paths"])
            artifacts = plan_artifact_producer.prepare_owner_envelope(
                arguments.owner_confirmation_file,
                arguments.owner_confirmation_sha256,
                arguments.state_evidence_file,
                arguments.state_evidence_sha256,
                arguments.variables_example_file,
                arguments.variables_example_sha256,
                arguments.backend_example_file,
                arguments.backend_example_sha256,
                arguments.operation_root,
                external_root=Path(paths["temporary_root"]),
                repository_root=repository,
            )
            for path, digest in artifacts:
                print(f"ARTIFACT={path}|SHA256={digest}")
            print("PLAN_OWNER_ENVELOPE_PREPARATION=PASS")
            print("TERRAFORM=NOT_RUN; AWS=NOT_RUN; BILLING=NOT_RUN")
            return 0
        if arguments.command == "prepare-plan-artifacts":
            repository = repository_root()
            configuration = load_lifecycle_config(repository / "configs/lifecycle/w5-004.json")
            paths = cast(dict[str, str], configuration["external_paths"])
            artifacts = plan_artifact_producer.prepare_plan_artifacts(
                arguments.owner_input_file,
                arguments.owner_input_sha256,
                arguments.operation_root,
                external_root=Path(paths["temporary_root"]),
                repository_root=repository,
            )
            for path, digest in artifacts:
                print(f"ARTIFACT={path}|SHA256={digest}")
            print("PLAN_ARTIFACT_PREPARATION=PASS")
            print("TERRAFORM=NOT_RUN; AWS=NOT_RUN; BILLING=NOT_RUN")
            return 0
        if getattr(arguments, "prepare_prerequisite_correction", False):
            if (
                arguments.command != "aws-verify"
                or not arguments.diagnostic
                or arguments.execute
                or arguments.environment != "sandbox"
                or arguments.target != "platform"
                or any(
                    getattr(arguments, key, False)
                    for key in (
                        "prerequisite_resolution",
                        "prerequisite_correction",
                        "resolution",
                        "resolution_followup",
                        "prepare_diagnostic",
                    )
                )
                or not arguments.owner_approval_file
                or not arguments.owner_approval_sha256
                or not arguments.source_sha256
                or not arguments.evidence_sha256
                or not arguments.evidence_identity_sha256
                or bool(arguments.charging_evidence_file)
                != bool(arguments.charging_evidence_sha256)
                or any(
                    getattr(arguments, key, None) is not None
                    for key in (
                        "request_file",
                        "request_sha256",
                        "runtime_file",
                        "runtime_sha256",
                    )
                )
            ):
                raise ContractError("CORRECTION_PREPARATION_EXACT_ARGUMENTS")
            repository = repository_root()
            config = load_lifecycle_config(repository / "configs/lifecycle/w5-004.json")
            paths = cast(dict[str, str], config["external_paths"])
            plan._build_owner_diagnostic_inputs(
                repository,
                Path(paths["temporary_root"]),
                arguments.source_sha256,
                resolution_only=True,
                correction=True,
                prepare_correction_inputs=True,
                prerequisite_hashes=(arguments.evidence_sha256, arguments.evidence_identity_sha256),
            )
            artifacts = plan.prepare_prerequisite_correction_inputs(
                repository,
                Path(paths["temporary_root"]),
                Path(arguments.owner_approval_file),
                arguments.owner_approval_sha256,
                clock=effective_clock,
                source_sha256=arguments.source_sha256,
                charging_input=(
                    Path(arguments.charging_evidence_file),
                    arguments.charging_evidence_sha256,
                )
                if arguments.charging_evidence_file
                else None,
            )
            for artifact_path, digest in artifacts:
                print(f"ARTIFACT={artifact_path}|SHA256={digest}")
            print("CORRECTION_INPUTS=DIAGNOSTIC_ONLY_COST_BLOCKED")
            return 0
        if getattr(arguments, "prerequisite_correction", False) and not getattr(
            arguments, "prerequisite_resolution", False
        ):
            raise ContractError("PREREQUISITE_FLAG_REQUIRED")
        if any(
            getattr(arguments, name, None) is not None
            for name in (
                "owner_approval_file",
                "owner_approval_sha256",
                "charging_evidence_file",
                "charging_evidence_sha256",
            )
        ):
            raise ContractError("CORRECTION_PREPARATION_FLAG_REQUIRED")
        if getattr(arguments, "prerequisite_resolution", False):
            if (
                arguments.command != "aws-verify"
                or not arguments.diagnostic
                or not arguments.execute
                or arguments.prepare_diagnostic
                or arguments.resolution
                or arguments.resolution_followup
                or arguments.environment != "sandbox"
                or arguments.target != "platform"
                or arguments.source_sha256 is None
                or arguments.evidence_sha256 is None
                or arguments.evidence_identity_sha256 is None
                or any(
                    getattr(arguments, key, None) is not None
                    for key in ("request_file", "request_sha256", "runtime_file", "runtime_sha256")
                )
            ):
                raise ContractError("PREREQUISITE_EXACT_ARGUMENTS_REQUIRED")
            repository = repository_root()
            config = load_lifecycle_config(repository / "configs/lifecycle/w5-004.json")
            paths = cast(dict[str, str], config["external_paths"])
            correction_options = {"correction": True} if arguments.prerequisite_correction else {}
            code, reason = plan.run_owner_prerequisite(
                repository,
                Path(paths["temporary_root"]),
                arguments.source_sha256,
                arguments.evidence_sha256,
                arguments.evidence_identity_sha256,
                clock=effective_clock,
                **correction_options,
            )
            print(f"EXECUTION_EXIT_CODE={code}")
            print(f"REASON_CODE={reason}")
            return code
        if getattr(arguments, "evidence_identity_sha256", None) is not None:
            raise ContractError("PREREQUISITE_FLAG_REQUIRED")
        if getattr(arguments, "resolution", False) or getattr(
            arguments, "resolution_followup", False
        ):
            if (
                arguments.command != "aws-verify"
                or not arguments.diagnostic
                or not arguments.execute
                or arguments.prepare_diagnostic
                or arguments.environment != "sandbox"
                or arguments.target != "platform"
                or arguments.source_sha256 is None
                or arguments.evidence_sha256 is None
                or (arguments.resolution and arguments.resolution_followup)
                or any(
                    getattr(arguments, key, None) is not None
                    for key in ("request_file", "request_sha256", "runtime_file", "runtime_sha256")
                )
            ):
                raise ContractError("RESOLUTION_EXACT_ARGUMENTS_REQUIRED")
            repository = repository_root()
            config = load_lifecycle_config(repository / "configs/lifecycle/w5-004.json")
            paths = cast(dict[str, str], config["external_paths"])
            selection = {"followup": True} if arguments.resolution_followup else {}
            code, reason = plan.run_owner_resolution(
                repository,
                Path(paths["temporary_root"]),
                arguments.source_sha256,
                arguments.evidence_sha256,
                clock=effective_clock,
                **selection,
            )
            print(f"EXECUTION_EXIT_CODE={code}")
            print(f"REASON_CODE={reason}")
            return code
        if getattr(arguments, "evidence_sha256", None) is not None:
            raise ContractError("RESOLUTION_FLAG_REQUIRED")
        if getattr(arguments, "prepare_diagnostic", False):
            if (
                not arguments.diagnostic
                or arguments.environment != "sandbox"
                or arguments.target != "platform"
                or arguments.execute
                or any(
                    getattr(arguments, key, None) is not None
                    for key in ("request_file", "request_sha256", "runtime_file", "runtime_sha256")
                )
                or arguments.source_sha256 is None
            ):
                raise ContractError("LOCAL_DIAGNOSTIC_PREPARATION_ARGUMENTS_REQUIRED")
            repository = repository_root()
            config = load_lifecycle_config(repository / "configs/lifecycle/w5-004.json")
            paths = cast(dict[str, str], config["external_paths"])
            artifacts = plan.prepare_owner_diagnostic(
                repository, Path(paths["temporary_root"]), arguments.source_sha256
            )
            for artifact_path, digest in artifacts:
                print(f"ARTIFACT={artifact_path}|SHA256={digest}")
            print("DIAGNOSTIC_ARTIFACT_PREPARATION=PASS")
            print("ARTIFACT_STATUS=READY_FOR_OWNER_REVIEW")
            print("AWS=NOT_RUN; RECOVERY_ELIGIBILITY=NOT_ESTABLISHED; APPLY=NOT_RUN")
            return 0
        if getattr(arguments, "source_sha256", None) is not None:
            raise ContractError("SOURCE_HASH_REQUIRES_LOCAL_DIAGNOSTIC_PREPARATION")
        if getattr(arguments, "execute", False):
            request_path = getattr(arguments, "request_file", None)
            request_hash = getattr(arguments, "request_sha256", None)
            if not isinstance(request_path, Path) or not isinstance(request_hash, str):
                raise ContractError("EXECUTION_REQUEST_AND_HASH_REQUIRED")
            if execution_services is None:
                config = load_lifecycle_config(repository_root() / "configs/lifecycle/w5-004.json")
                paths = cast(dict[str, str], config["external_paths"])
                external = Path(paths["temporary_root"])
                repository = repository_root()
            else:
                external, repository = (
                    execution_services.external_root,
                    execution_services.repository_root,
                )
            request_path_bound = ensure_external_path(request_path, external, repository)
            if not request_path_bound.is_file() or request_path_bound.stat().st_size > 1024 * 1024:
                raise ContractError("EXECUTION_REQUEST_SIZE_OR_TYPE")
            payload = request_path_bound.read_bytes()
            if sha256_bytes(payload) != request_hash:
                raise ContractError("EXECUTION_REQUEST_HASH_MISMATCH")
            request_value = decode_json_strict(payload)
            if not isinstance(request_value, dict):
                raise ContractError("EXECUTION_REQUEST_OBJECT_REQUIRED")
            diagnostic = request_value.get("schema_version") == DIAGNOSTIC_SCHEMA_VERSION
            if diagnostic != bool(getattr(arguments, "diagnostic", False)) or (
                diagnostic and arguments.command != "aws-verify"
            ):
                raise ContractError("DIAGNOSTIC_COMMAND_SCHEMA_MISMATCH")
            if (
                "environment" in request_value
                and request_value["environment"] != arguments.environment
            ):
                raise ContractError("CLI_REQUEST_ENVIRONMENT_MISMATCH")
            if "target" in request_value and request_value["target"] != getattr(
                arguments, "target", None
            ):
                raise ContractError("CLI_REQUEST_TARGET_MISMATCH")
            _validate_cli_mutation_binding(arguments, payload, external, repository)
            if execution_services is None:
                runtime_path = getattr(arguments, "runtime_file", None)
                runtime_hash = getattr(arguments, "runtime_sha256", None)
                if not isinstance(runtime_path, Path) or not isinstance(runtime_hash, str):
                    print(
                        "PROVIDER_UNAVAILABLE: bound runtime configuration required",
                        file=sys.stderr,
                    )
                    return 3
                created_services = plan.production_coordinator(
                    runtime_path,
                    runtime_hash,
                    request_payload=payload,
                    repository=repository,
                    clock=effective_clock,
                )
                if isinstance(created_services, plan.RepositoryDiagnosticCoordinator) and bool(
                    getattr(arguments, "w12_retention_proof_root", None)
                ):
                    raise ContractError("DIAGNOSTIC_W12_PROOF_ROOT_FORBIDDEN")
                execution_services = cast(LifecycleExecutionServices, created_services)
            if execution_services is None:
                raise ContractError("EXECUTION_SERVICES_UNAVAILABLE")
            proof_roots = W12RuntimeProofRoots(
                tuple(getattr(arguments, "w12_retention_proof_root", ()))
            )
            if proof_roots.paths:
                code, reason = execution_services.execute_request(
                    arguments.command, payload, proof_roots
                )
            else:
                code, reason = execution_services.execute_request(arguments.command, payload)
            if (
                code not in {0, 1, 2, 3, 4}
                or not reason
                or any(character not in ascii_uppercase + digits + "_" for character in reason)
            ):
                raise ContractError("EXECUTION_RESULT_MALFORMED")
            print(
                f"EXECUTION_EXIT_CODE={code}\nREASON_CODE={reason}",
                file=sys.stdout if code == 0 else sys.stderr,
            )
            return code
        if getattr(arguments, "diagnostic", False):
            raise ContractError("DIAGNOSTIC_EXPLICIT_EXECUTION_REQUIRED")
        if any(
            getattr(arguments, name, None) is not None
            for name in (
                "request_file",
                "request_sha256",
                "runtime_file",
                "runtime_sha256",
            )
        ):
            raise ContractError("EXECUTION_MODE_REQUIRED_FOR_REQUEST")
        if arguments.command == "validate":
            errors = validate_repository()
            if errors:
                for error in errors:
                    print(f"ERROR: {error}", file=sys.stderr)
                return 1
            print("CODE-STAGE VALIDATION PASS: approved repository contract is present")
            return 0

        if arguments.command in {
            "bootstrap-plan",
            "platform-plan",
            "policy-review",
            "cost-review",
            "aws-verify",
            "destroy-plan",
        }:
            result = plan.validate_request(arguments.environment, arguments.target)
        elif arguments.command == "verify-clean":
            proof_roots = W12RuntimeProofRoots(tuple(arguments.w12_retention_proof_root))
            proof_repository: Path | None = None
            proof_external: Path | None = None
            if proof_roots.paths:
                proof_repository = repository_root()
                config = load_lifecycle_config(proof_repository / "configs/lifecycle/w5-004.json")
                paths = cast(dict[str, str], config["external_paths"])
                proof_external = Path(paths["temporary_root"])
            result = verify_clean(
                effective_inventory,
                cast(str, arguments.environment),
                effective_clock.now(),
                proof_roots=proof_roots,
                external_root=proof_external,
                repository_root=proof_repository,
            )
        else:
            approval = load_approval_record(cast(Path, arguments.approval_record))
            if arguments.command == "bootstrap-apply":
                request = _mutation_request(arguments, Action.BOOTSTRAP_APPLY)
                result = bootstrap.validate_request(
                    request, approval, effective_usage, effective_clock.now()
                )
            elif arguments.command == "platform-apply":
                request = _mutation_request(arguments, Action.PLATFORM_APPLY)
                result = deploy.validate_request(
                    request, approval, effective_usage, effective_clock.now()
                )
            elif arguments.command == "infrastructure-rollback":
                request = _mutation_request(arguments, Action.INFRASTRUCTURE_ROLLBACK)
                result = rollback.validate_request(
                    request, approval, effective_usage, effective_clock.now()
                )
            elif arguments.command in {
                "purge-sandbox",
                "platform-destroy",
                "bootstrap-destroy",
            }:
                mode = DestroyMode(arguments.command)
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
    except (OSError, ValueError, TypeError):
        print("REASON_CODE=EXECUTION_INPUT_OR_ADAPTER_FAILURE", file=sys.stderr)
        return 1

    output = sys.stdout if result.exit_code == 0 else sys.stderr
    print(result.message, file=output)
    return int(result.exit_code)
