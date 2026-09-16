"""Bounded Terraform 1.16.1 process adapter for saved-plan workflows."""

from __future__ import annotations

import re
import subprocess  # noqa: S404 - exact argv execution is isolated in this adapter.
import threading
from collections.abc import Iterator, Mapping, Sequence
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .contracts import ContractError, VerifiedExecutionContext, validate_sha256
from .lifecycle_io import (
    canonical_json_bytes,
    decode_json_strict,
    ensure_external_path,
    private_tool_directory,
    private_transient_bytes,
    sha256_bytes,
    sha256_file,
    validate_original_ancestors,
)

TERRAFORM_VERSION = "1.16.1"
AWS_PROVIDER_VERSION = "6.55.0"
DEFAULT_TIMEOUT_SECONDS = 900
MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024


class ProcessOutcomeUncertain(ContractError):
    """The adapter cannot prove process completion; never retry a mutation."""


def _require_bound_process(
    context: VerifiedExecutionContext,
    cwd: Path,
    environment: Mapping[str, str],
) -> None:
    """A direct adapter call cannot select another working root or backend environment."""
    validate_original_ancestors(cwd)
    inputs = dict(context.package.identities.inputs)
    if inputs.get("runtime/terraform-root") != sha256_bytes(
        canonical_json_bytes(str(cwd.resolve(strict=True)))
    ) or inputs.get("runtime/terraform-environment") != sha256_bytes(
        canonical_json_bytes(controlled_environment(environment, cost_child=False))
    ):
        raise ContractError("DISPATCH_PROCESS_BOUNDARY_DRIFT")


def controlled_environment(environment: Mapping[str, str], *, cost_child: bool) -> dict[str, str]:
    """Use explicit values only; never inherit ambient credentials or routing."""
    permitted = {
        "SYSTEMROOT",
        "WINDIR",
        "PATH",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
        "TF_DATA_DIR",
        "TF_PLUGIN_CACHE_DIR",
        "TF_IN_AUTOMATION",
        "TF_INPUT",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_EC2_METADATA_DISABLED",
        "GIT_OPTIONAL_LOCKS",
        "LC_ALL",
        "LANG",
        "PYTHONDONTWRITEBYTECODE",
    }
    if cost_child:
        permitted = {"INFRACOST_API_KEY", "SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}
    result: dict[str, str] = {}
    for key, value in environment.items():
        normalized = key.upper()
        if normalized not in permitted or normalized in result or "\x00" in value:
            raise ContractError("CHILD_ENVIRONMENT_NOT_APPROVED")
        result[normalized] = value
    if result.get("AWS_PROFILE", "default") != "default" or any(
        result.get(name, "ap-southeast-1") != "ap-southeast-1"
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
    ):
        raise ContractError("CHILD_AWS_ROUTING_MISMATCH")
    if cost_child and any(key.startswith("AWS_") for key in result):
        raise ContractError("COST_CHILD_AWS_ENVIRONMENT_PROHIBITED")
    return result


@dataclass(frozen=True)
class ProcessResult:
    """Sanitized process result returned by an injected runner."""

    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """Injection boundary used by tests and the later owner runner."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        """Run one argv-only process without a command shell."""
        ...


class SubprocessCommandRunner:
    """Concrete argv-only runner; never invokes a shell or echoes its environment."""

    def __init__(
        self, *, repository_root: Path | None = None, external_root: Path | None = None
    ) -> None:
        self._repository_root = repository_root
        self._external_root = external_root

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        return self._execute(
            arguments,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            execution_context=None,
        )

    def run_reviewed_mutation(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
        execution_context: VerifiedExecutionContext,
    ) -> ProcessResult:
        return self._execute(
            arguments,
            cwd=cwd,
            environment=environment,
            timeout_seconds=timeout_seconds,
            execution_context=execution_context,
        )

    def _execute(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
        execution_context: VerifiedExecutionContext | None,
    ) -> ProcessResult:
        if not arguments or not Path(arguments[0]).is_absolute() or timeout_seconds <= 0:
            raise ContractError("PROCESS_ARGUMENT_BOUNDARY")
        name = Path(arguments[0]).name.casefold().removesuffix(".exe")
        verbs = {
            "terraform": {"version", "init", "plan", "show", "apply", "state"},
            "git": {"--version", "rev-parse", "symbolic-ref", "ls-tree", "ls-files", "status"},
            "opa": {"version", "eval"},
            "infracost": {"--version", "breakdown"},
        }
        if name not in verbs or len(arguments) < 2 or arguments[1] not in verbs[name]:
            raise ContractError("PROCESS_COMMAND_NOT_SUPPORTED")
        if name == "infracost":
            if arguments[1] == "--version":
                if len(arguments) != 2:
                    raise ContractError("INFRACOST_COMMAND_NOT_EXACT")
            elif (
                len(arguments) != 8
                or arguments[2] != "--path"
                or tuple(arguments[4:7]) != ("--format", "json", "--out-file")
                or not Path(arguments[3]).is_absolute()
                or not Path(arguments[7]).is_absolute()
            ):
                raise ContractError("INFRACOST_COMMAND_NOT_EXACT")
        if (
            name == "terraform"
            and arguments[1] == "state"
            and tuple(arguments[1:]) != ("state", "pull")
        ):
            raise ContractError("PROCESS_STATE_MUTATION_PROHIBITED")
        if name == "terraform" and arguments[1] == "init":
            tail = tuple(arguments[2:])
            if tail[:2] != ("-input=false", "-lockfile=readonly") or len(tail) not in {2, 3}:
                raise ContractError("PROCESS_INITIALIZATION_ARGUMENTS_NOT_APPROVED")
            if (
                len(tail) == 3
                and tail[2] != "-backend=false"
                and not (
                    tail[2].startswith("-backend-config=")
                    and Path(tail[2].removeprefix("-backend-config=")).is_absolute()
                )
            ):
                raise ContractError("PROCESS_INITIALIZATION_ARGUMENTS_NOT_APPROVED")
        if (
            name == "terraform"
            and arguments[1] == "plan"
            and any(
                argument.startswith(("-refresh-only", "-lock=false", "-state=", "-state-out="))
                for argument in arguments[2:]
            )
        ):
            raise ContractError("PROCESS_PLAN_OVERRIDE_PROHIBITED")
        if len(arguments) > 1 and arguments[1] == "apply":
            if not isinstance(execution_context, VerifiedExecutionContext):
                raise ContractError("PROCESS_MUTATION_CONTEXT_REQUIRED")
            package = execution_context.package
            if (
                len(arguments) != 5
                or tuple(arguments[2:4]) != ("-input=false", "-auto-approve")
                or package.artifact.kind != "saved-plan"
                or ("terraform", arguments[0], TERRAFORM_VERSION, sha256_file(Path(arguments[0])))
                not in package.identities.tools
                or sha256_file(Path(arguments[4])) != package.artifact.sha256
            ):
                raise ContractError("PROCESS_MUTATION_ARGUMENTS_NOT_BOUND")
            _require_bound_process(execution_context, cwd, environment)
            execution_context.claim_dispatch(package.action, package.artifact.sha256)
        elif execution_context is not None:
            raise ContractError("PROCESS_MUTATION_COMMAND_NOT_SUPPORTED")
        child_environment = controlled_environment(
            environment,
            cost_child=Path(arguments[0]).name.casefold() in {"infracost", "infracost.exe"},
        )
        with self._isolated_tool_launch(name, arguments[1], cwd, child_environment) as launch:
            launch_cwd, launch_environment = launch
            return self._capture(
                arguments,
                cwd=launch_cwd,
                environment=launch_environment,
                timeout_seconds=timeout_seconds,
            )

    @contextmanager
    def _isolated_tool_launch(
        self, name: str, verb: str, cwd: Path, environment: dict[str, str]
    ) -> Iterator[tuple[Path, dict[str, str]]]:
        """Synthesize private launch settings only after validating the bound caller input."""
        if name not in {"terraform", "infracost"}:
            yield cwd, environment
            return
        if self._repository_root is None or self._external_root is None:
            raise ContractError("TOOL_ISOLATION_ROOTS_REQUIRED")
        repository = self._repository_root
        external = self._external_root
        # Keep these generated paths out of the owner's environment identity: the
        # immutable adapter code selects them after _require_bound_process checks.
        # Caller-supplied configuration, endpoint, proxy and update overrides remain
        # rejected by controlled_environment before reaching this point.
        aws_home: Path | None = None
        if name == "terraform" and verb in {"init", "plan", "apply", "state"}:
            import os

            home_value = environment.get("USERPROFILE" if os.name == "nt" else "HOME")
            if not home_value or not Path(home_value).is_absolute():
                raise ContractError("APPROVED_AWS_PROFILE_HOME_REQUIRED")
            aws_home = Path(home_value)
            validate_original_ancestors(aws_home)
            if not aws_home.is_dir():
                raise ContractError("APPROVED_AWS_PROFILE_HOME_REQUIRED")
            for filename in ("config", "credentials"):
                validate_original_ancestors(aws_home / ".aws" / filename)
        if name == "infracost" and verb == "breakdown":
            key = environment.get("INFRACOST_API_KEY", "")
            if not key or any(character in key for character in ("\x00", "\r", "\n")):
                raise ContractError("PROCESS_PRICING_CREDENTIAL_UNAVAILABLE")
        with private_tool_directory(external, repository) as home, ExitStack() as files:
            child = {
                **environment,
                **dict.fromkeys(
                    (
                        "HOME",
                        "USERPROFILE",
                        "APPDATA",
                        "LOCALAPPDATA",
                        "XDG_CONFIG_HOME",
                        "XDG_CACHE_HOME",
                        "TEMP",
                        "TMP",
                    ),
                    str(home),
                ),
            }

            def private_file(relative: str, payload: bytes) -> Path:
                return files.enter_context(
                    private_transient_bytes(
                        home / relative, payload, allowed_root=external, repository_root=repository
                    )
                )

            if name == "terraform":
                configuration = private_file(
                    "terraform.rc",
                    b"disable_checkpoint = true\nprovider_installation {\n  direct {}\n}\n",
                )
                child["CHECKPOINT_DISABLE"] = "1"
                child["TF_CLI_CONFIG_FILE"] = str(configuration)
                if aws_home is not None:
                    child["AWS_PROFILE"] = "default"
                    child["AWS_EC2_METADATA_DISABLED"] = "true"
                    child["AWS_SHARED_CREDENTIALS_FILE"] = str(aws_home / ".aws" / "credentials")
                    child["AWS_CONFIG_FILE"] = str(aws_home / ".aws" / "config")
                yield cwd, child
            else:
                # v0.10.45 always loads ~/.config/infracost and creates an install
                # ID at startup. Seed only this owned, non-secret state/config.
                private_file(
                    ".config/infracost/.state.json",
                    canonical_json_bytes({"installId": home.name}),
                )
                private_file(
                    ".config/infracost/configuration.yml",
                    b"version: '0.1'\nenable_cloud: false\nenable_cloud_upload: false\n",
                )
                child.update(
                    {
                        "INFRACOST_SKIP_UPDATE_CHECK": "true",
                        "INFRACOST_DISABLE_ENVFILE": "true",
                        "INFRACOST_ENABLE_CLOUD": "false",
                        "INFRACOST_ENABLE_CLOUD_UPLOAD": "false",
                        "INFRACOST_ENABLE_DASHBOARD": "false",
                        "INFRACOST_PRICING_CACHE_DISABLED": "true",
                        "INFRACOST_PRICING_API_ENDPOINT": "https://pricing.api.infracost.io",
                        "INFRACOST_CURRENCY": "USD",
                    }
                )
                if verb == "--version":
                    child.pop("INFRACOST_API_KEY", None)
                yield home, child

    @staticmethod
    def _capture(
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> ProcessResult:
        """Capture one already-validated launch; never inherit the parent environment."""
        chunks: list[bytearray] = [bytearray(), bytearray()]
        overflow = threading.Event()
        try:
            process = subprocess.Popen(  # noqa: S603
                tuple(arguments),
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
            )
            from typing import BinaryIO

            def drain(stream: BinaryIO, destination: bytearray) -> None:
                try:
                    while block := stream.read(65536):
                        if len(destination) + len(block) > MAX_PROCESS_OUTPUT_BYTES:
                            overflow.set()
                            process.kill()
                            break
                        destination.extend(block)
                except OSError:
                    overflow.set()
                finally:
                    stream.close()

            if process.stdout is None or process.stderr is None:
                process.kill()
                raise ProcessOutcomeUncertain("PROCESS_CAPTURE_UNAVAILABLE")
            readers = [
                threading.Thread(target=drain, args=(process.stdout, chunks[0]), daemon=True),
                threading.Thread(target=drain, args=(process.stderr, chunks[1]), daemon=True),
            ]
            for reader in readers:
                reader.start()
            try:
                process.wait(timeout=timeout_seconds)
            except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
                process.kill()
                process.wait(timeout=10)
                raise ProcessOutcomeUncertain("PROCESS_TIMEOUT_OR_CANCELLED") from exc
            finally:
                for reader in readers:
                    reader.join(timeout=10)
            if overflow.is_set() or any(reader.is_alive() for reader in readers):
                raise ProcessOutcomeUncertain("PROCESS_OUTPUT_LIMIT_OR_INCOMPLETE")
            return ProcessResult(
                process.returncode,
                bytes(chunks[0]).decode("utf-8", errors="strict"),
                bytes(chunks[1]).decode("utf-8", errors="strict"),
            )
        except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
            raise ProcessOutcomeUncertain("PROCESS_COMPLETION_UNPROVEN") from exc


class TerraformRunner:
    """Fail-closed saved-plan Terraform adapter with no implicit re-plan."""

    def __init__(
        self,
        *,
        executable: Path,
        repository_root: Path,
        external_root: Path,
        runner: CommandRunner,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        executable_sha256: str | None = None,
        environment: Mapping[str, str] | None = None,
        data_root: Path | None = None,
    ) -> None:
        validate_original_ancestors(executable)
        self._executable = executable.resolve(strict=False)
        self._repository_root = repository_root.resolve(strict=True)
        self._external_root = external_root.resolve(strict=False)
        self._runner = runner
        self._timeout_seconds = timeout_seconds
        self._executable_sha256 = executable_sha256
        self._environment = controlled_environment(environment or {}, cost_child=False)
        self._data_root = ensure_external_path(
            data_root or self._external_root / "terraform-data",
            self._external_root,
            self._repository_root,
        )

    def _root(self, terraform_root: Path) -> Path:
        validate_original_ancestors(terraform_root)
        resolved = terraform_root.resolve(strict=True)
        try:
            resolved.relative_to(self._repository_root)
        except ValueError as exc:
            raise ContractError("Terraform root is outside the repository") from exc
        if resolved not in {
            self._repository_root / "infra" / "bootstrap",
            self._repository_root / "infra" / "environments" / "sandbox",
        }:
            raise ContractError("Terraform root is not approved")
        return resolved

    def _run(
        self,
        terraform_root: Path,
        arguments: Sequence[str],
        *,
        execution_context: VerifiedExecutionContext | None = None,
    ) -> ProcessResult:
        root = self._root(terraform_root)
        state_read = tuple(arguments) == ("state", "pull")
        if not arguments or (
            arguments[0] not in {"version", "init", "plan", "show", "apply"} and not state_read
        ):
            raise ContractError("TERRAFORM_COMMAND_NOT_APPROVED")
        forbidden = {"force-unlock", "import", "state", "refresh"}
        if not state_read and any(argument in forbidden for argument in arguments):
            raise ContractError("Terraform operation is prohibited")
        if self._executable_sha256 is None:
            raise ContractError("TERRAFORM_EXECUTABLE_HASH_REQUIRED")
        validate_sha256(self._executable_sha256)
        if sha256_file(self._executable) != self._executable_sha256:
            raise ContractError("TERRAFORM_EXECUTABLE_CHANGED")
        if arguments[0] == "apply":
            if not isinstance(execution_context, VerifiedExecutionContext):
                raise ContractError("VERIFIED_EXECUTION_CONTEXT_REQUIRED")
            if (
                len(arguments) != 4
                or tuple(arguments[1:3]) != ("-input=false", "-auto-approve")
                or execution_context.package.artifact.kind != "saved-plan"
            ):
                raise ContractError("EXACT_SAVED_PLAN_ARGUMENTS_REQUIRED")
            expected_tool = (
                "terraform",
                str(self._executable),
                TERRAFORM_VERSION,
                self._executable_sha256,
            )
            expected_root = self._repository_root / (
                "infra/bootstrap"
                if execution_context.package.target == "bootstrap"
                else "infra/environments/sandbox"
            )
            if (
                expected_tool not in execution_context.package.identities.tools
                or root != expected_root
            ):
                raise ContractError("DISPATCH_TOOL_OR_ROOT_MISMATCH")
            artifact = ensure_external_path(
                Path(arguments[3]), self._external_root, self._repository_root
            )
            if sha256_file(artifact) != execution_context.package.artifact.sha256:
                raise ContractError("DISPATCH_ARTIFACT_DRIFT")
        process_arguments = (str(self._executable), *arguments)
        process_environment = {
            **self._environment,
            "TF_DATA_DIR": str(self._data_root / root.name),
            "TF_IN_AUTOMATION": "1",
        }
        if arguments[0] == "apply":
            if execution_context is None:
                raise ContractError("VERIFIED_EXECUTION_CONTEXT_REQUIRED")
            _require_bound_process(execution_context, root, process_environment)
            if not isinstance(self._runner, SubprocessCommandRunner):
                execution_context.claim_dispatch(
                    execution_context.package.action, execution_context.package.artifact.sha256
                )
        if arguments[0] == "apply" and isinstance(self._runner, SubprocessCommandRunner):
            if execution_context is None:
                raise ContractError("VERIFIED_EXECUTION_CONTEXT_REQUIRED")
            return self._check_result(
                self._runner.run_reviewed_mutation(
                    process_arguments,
                    cwd=root,
                    environment=process_environment,
                    timeout_seconds=self._timeout_seconds,
                    execution_context=execution_context,
                ),
                arguments,
            )
        result = self._runner.run(
            process_arguments,
            cwd=root,
            environment=process_environment,
            timeout_seconds=self._timeout_seconds,
        )
        return self._check_result(result, arguments)

    @staticmethod
    def _check_result(result: ProcessResult, arguments: Sequence[str]) -> ProcessResult:
        accepted = {0, 2} if arguments[0] == "plan" and "-detailed-exitcode" in arguments else {0}
        if result.returncode not in accepted:
            detail = result.stderr.casefold()
            if "accessdenied" in detail or "not authorized" in detail:
                reason = "TERRAFORM_AUTHORIZATION_FAILURE_OBSERVED"
            elif "state lock" in detail or "lock info" in detail:
                reason = "TERRAFORM_STATE_LOCK_RECONCILIATION_REQUIRED"
            elif "saved plan is stale" in detail or "state was changed" in detail:
                reason = "TERRAFORM_SAVED_PLAN_STATE_DRIFT"
            elif "backend initialization required" in detail:
                reason = "TERRAFORM_BACKEND_INITIALIZATION_REQUIRED"
            else:
                reason = "TERRAFORM_OPERATION_FAILED_INDETERMINATE"
            raise ContractError(reason)
        return result

    def verify_version(self, terraform_root: Path) -> None:
        """Require exact Terraform version and Windows AMD64 identity."""
        result = self._run(terraform_root, ("version", "-json"))
        payload = decode_json_strict(result.stdout.encode("utf-8"))
        if not isinstance(payload, dict):
            raise ContractError("Terraform version output is malformed")
        if payload.get("terraform_version") != TERRAFORM_VERSION:
            raise ContractError("Terraform version must be exactly 1.16.1")
        if payload.get("platform") != "windows_amd64":
            raise ContractError("Terraform platform must be windows_amd64")

    def verify_backend(
        self,
        terraform_root: Path,
        configuration: Path,
        expected_hash: str,
    ) -> dict[str, object]:
        """Bind initialized local/S3 backend metadata to the exact reviewed literal input."""
        root = self._root(terraform_root)
        source = ensure_external_path(configuration, self._external_root, self._repository_root)
        if sha256_file(source) != expected_hash or source.stat().st_size > 65536:
            raise ContractError("BACKEND_CONFIGURATION_DRIFT")
        expected: dict[str, object] = {}
        allowed = (
            {"path"}
            if root.name == "bootstrap"
            else {
                "bucket",
                "key",
                "region",
                "profile",
                "encrypt",
                "kms_key_id",
                "dynamodb_table",
                "use_lockfile",
            }
        )
        for line in source.read_text(encoding="utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            match = re.fullmatch(r'\s*([a-z_]+)\s*=\s*("(?:[^"\\]|\\.)*"|true|false)\s*', line)
            if match is None or match[1] not in allowed or match[1] in expected:
                raise ContractError("BACKEND_CONFIGURATION_NOT_LITERAL_OR_DUPLICATED")
            expected[match[1]] = decode_json_strict(match[2].encode("utf-8"))
        required = (
            {"path"}
            if root.name == "bootstrap"
            else {"bucket", "key", "region", "encrypt", "kms_key_id", "dynamodb_table"}
        )
        if not required.issubset(expected):
            raise ContractError("BACKEND_CONFIGURATION_INCOMPLETE")
        if root.name != "bootstrap" and (
            expected["region"] != "ap-southeast-1"
            or expected["encrypt"] is not True
            or expected.get("profile", "default") != "default"
        ):
            raise ContractError("BACKEND_SCOPE_OR_ENCRYPTION_INVALID")
        metadata = ensure_external_path(
            self._data_root / root.name / "terraform.tfstate",
            self._external_root,
            self._repository_root,
        )
        if not metadata.is_file() or metadata.stat().st_size > 1024 * 1024:
            raise ContractError("INITIALIZED_BACKEND_METADATA_REQUIRED")
        value = decode_json_strict(metadata.read_bytes())
        backend = value.get("backend") if isinstance(value, dict) else None
        if not isinstance(backend, dict) or backend.get("type") != (
            "local" if root.name == "bootstrap" else "s3"
        ):
            raise ContractError("INITIALIZED_BACKEND_TYPE_MISMATCH")
        actual = backend.get("config")
        if not isinstance(actual, dict) or any(
            actual.get(key) != item for key, item in expected.items()
        ):
            raise ContractError("INITIALIZED_BACKEND_CONFIGURATION_MISMATCH")
        # Defaults may be materialized, but credentials, alternate endpoints and routing
        # options must never be smuggled through existing initialization metadata.
        harmless_defaults = {"workspace_key_prefix": "env:", "max_retries": 5}
        for key, item in actual.items():
            if key in expected or item in (None, "", False, [], {}):
                continue
            if key in harmless_defaults and item == harmless_defaults[key]:
                continue
            raise ContractError("INITIALIZED_BACKEND_UNAPPROVED_OPTION")
        return expected

    def initialize(
        self,
        terraform_root: Path,
        *,
        backend: bool,
        backend_config: Path | None = None,
    ) -> None:
        """Initialize only with explicit backend selection and readonly locks."""
        root = self._root(terraform_root)
        arguments = ["init", "-input=false", "-lockfile=readonly"]
        if not backend:
            arguments.append("-backend=false")
        elif backend_config is not None:
            config = ensure_external_path(
                backend_config, self._external_root, self._repository_root
            )
            if not config.is_file():
                raise ContractError("external backend configuration is unavailable")
            arguments.append(f"-backend-config={config}")
        elif root == self._repository_root / "infra" / "environments" / "sandbox":
            raise ContractError("sandbox initialization requires external backend configuration")
        self._run(terraform_root, tuple(arguments))

    def create_saved_plan(
        self,
        terraform_root: Path,
        *,
        variables_file: Path,
        resource_expiry_file: Path,
        output_file: Path,
        destroy: bool = False,
    ) -> None:
        """Create an external saved plan; never apply it automatically."""
        variables = ensure_external_path(variables_file, self._external_root, self._repository_root)
        expiry_variables = ensure_external_path(
            resource_expiry_file, self._external_root, self._repository_root
        )
        output = ensure_external_path(output_file, self._external_root, self._repository_root)
        if not variables.is_file() or not expiry_variables.is_file():
            raise ContractError("approved external Terraform variables are unavailable")
        if output.exists():
            raise ContractError("saved plan target already exists")
        arguments = [
            "plan",
            "-detailed-exitcode",
            "-input=false",
            "-lock-timeout=0s",
            f"-var-file={variables}",
            f"-var-file={expiry_variables}",
            f"-out={output}",
        ]
        if destroy:
            arguments.append("-destroy")
        self._run(terraform_root, tuple(arguments))

    def show_plan_json(self, terraform_root: Path, saved_plan: Path) -> bytes:
        """Return exact plan JSON bytes for redaction and policy evaluation."""
        plan = ensure_external_path(saved_plan, self._external_root, self._repository_root)
        if not plan.is_file():
            raise ContractError("saved plan is unavailable")
        result = self._run(terraform_root, ("show", "-json", str(plan)))
        return result.stdout.encode("utf-8")

    def pull_state(self, terraform_root: Path) -> bytes:
        """Read the configured state into memory; no state-writing command is supported."""
        return self._run(terraform_root, ("state", "pull")).stdout.encode("utf-8")

    def apply_saved_plan(
        self,
        terraform_root: Path,
        saved_plan: Path,
        expected_sha256: str,
        *,
        execution_context: VerifiedExecutionContext | None = None,
    ) -> None:
        """Dispatch only a bound saved artifact through the shared low-level gate."""
        if not isinstance(execution_context, VerifiedExecutionContext):
            raise ContractError("VERIFIED_EXECUTION_CONTEXT_REQUIRED")
        if (
            "terraform",
            str(self._executable),
            TERRAFORM_VERSION,
            self._executable_sha256,
        ) not in execution_context.package.identities.tools:
            raise ContractError("DISPATCH_TOOL_REVIEW_MISMATCH")
        expected_root = (
            "bootstrap" if execution_context.package.target == "bootstrap" else "sandbox"
        )
        if self._root(terraform_root).name != expected_root:
            raise ContractError("EXECUTION_ROOT_MISMATCH")
        execution_context.revalidate(
            execution_context.package.action, expected_sha256, consumed=True
        )
        plan = ensure_external_path(saved_plan, self._external_root, self._repository_root)
        if sha256_file(plan) != expected_sha256:
            raise ContractError("saved plan bytes do not match the approved SHA-256")
        self._run(
            terraform_root,
            ("apply", "-input=false", "-auto-approve", str(plan)),
            execution_context=execution_context,
        )


class GitObservationRunner:
    """Read-only fixed Git queries for the approved raw-byte identity scope."""

    def __init__(
        self,
        executable: Path,
        digest: str,
        version: str,
        runner: CommandRunner,
        repository_root: Path,
        environment: Mapping[str, str],
    ) -> None:
        self.executable = executable
        self.digest = digest
        self.version = version
        self.runner = runner
        self.repository_root = repository_root
        self.environment = {**environment, "GIT_OPTIONAL_LOCKS": "0"}

    def read(self, kind: str) -> bytes:
        from .lifecycle_io import LIFECYCLE_BASELINE_HEAD

        queries = {
            "head": ("rev-parse", "HEAD"),
            "branch": ("symbolic-ref", "--short", "HEAD"),
            "tree": ("ls-tree", "-r", "--name-only", "-z", LIFECYCLE_BASELINE_HEAD),
            "index": ("ls-files", "--stage", "-z"),
            "status": ("status", "--porcelain=v1", "-z", "--untracked-files=all"),
        }
        if kind not in queries or sha256_file(self.executable) != self.digest:
            raise ContractError("GIT_QUERY_OR_EXECUTABLE_NOT_APPROVED")
        version = self.runner.run(
            (str(self.executable), "--version"),
            cwd=self.repository_root,
            environment=self.environment,
            timeout_seconds=30,
        )
        if version.returncode != 0 or version.stdout.splitlines() != [
            f"git version {self.version}"
        ]:
            raise ContractError("GIT_VERSION_MISMATCH")
        result = self.runner.run(
            (str(self.executable), *queries[kind]),
            cwd=self.repository_root,
            environment=self.environment,
            timeout_seconds=60,
        )
        if result.returncode != 0:
            raise ContractError("GIT_OBSERVATION_FAILED")
        return result.stdout.encode("utf-8")
