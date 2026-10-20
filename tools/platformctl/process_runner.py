"""Provider-neutral, argv-only bounded process execution contracts."""

from __future__ import annotations

import codecs
import subprocess  # noqa: S404 - shell-free execution is the purpose of this boundary.
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from .contracts import ContractError, validate_sha256

MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
PROCESS_ENVIRONMENT_ALLOWLIST = frozenset(
    {
        "AWS_CONFIG_FILE",
        "AWS_DEFAULT_REGION",
        "AWS_EC2_METADATA_DISABLED",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_SHARED_CREDENTIALS_FILE",
        "CHECKPOINT_DISABLE",
        "GIT_OPTIONAL_LOCKS",
        "HOME",
        "INFRACOST_API_KEY",
        "INFRACOST_CURRENCY",
        "INFRACOST_DISABLE_ENVFILE",
        "INFRACOST_ENABLE_CLOUD",
        "INFRACOST_ENABLE_CLOUD_UPLOAD",
        "INFRACOST_ENABLE_DASHBOARD",
        "INFRACOST_PRICING_API_ENDPOINT",
        "INFRACOST_PRICING_CACHE_DISABLED",
        "INFRACOST_SKIP_UPDATE_CHECK",
        "LANG",
        "LC_ALL",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "SYSTEMROOT",
        "TEMP",
        "TF_CLI_CONFIG_FILE",
        "TF_DATA_DIR",
        "TF_IN_AUTOMATION",
        "TF_INPUT",
        "TF_PLUGIN_CACHE_DIR",
        "TMP",
        "USERPROFILE",
        "WINDIR",
    }
)


class ProcessClassification(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"
    INDETERMINATE = "INDETERMINATE"


class ResultCardinality(StrEnum):
    ZERO = "ZERO"
    ONE = "ONE"
    MANY = "MANY"


class PowerShellHost(StrEnum):
    WINDOWS_POWERSHELL_5_1 = "windows-powershell-5.1"
    POWERSHELL_7 = "powershell-7"


class ProcessOutcomeUncertain(ContractError):
    """The boundary cannot prove completion and must never report PASS."""


@dataclass(frozen=True)
class ProcessResult:
    """Content-bounded process result; legacy fields remain positional."""

    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float = 0.0
    classification: ProcessClassification | None = None
    executable_sha256: str | None = None
    executable_version: str | None = None
    progress: tuple[str, ...] = ()

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and self.classification in {
            None,
            ProcessClassification.SUCCEEDED,
        }


@dataclass(frozen=True)
class ProcessRequest:
    argv: tuple[str, ...]
    cwd: Path
    environment: tuple[tuple[str, str], ...]
    timeout_seconds: int
    executable_sha256: str
    executable_version: str | None = None

    def validate(self) -> None:
        if not self.argv or not Path(self.argv[0]).is_absolute():
            raise ContractError("PROCESS_EXECUTABLE_MUST_BE_ABSOLUTE")
        if any(not item or "\x00" in item for item in self.argv):
            raise ContractError("PROCESS_ARGUMENT_INVALID")
        if self.timeout_seconds <= 0:
            raise ContractError("PROCESS_TIMEOUT_INVALID")
        if not self.cwd.is_absolute() or not self.cwd.is_dir():
            raise ContractError("PROCESS_WORKING_DIRECTORY_INVALID")
        validate_sha256(self.executable_sha256)
        names = [name.upper() for name, _value in self.environment]
        if len(names) != len(set(names)):
            raise ContractError("PROCESS_ENVIRONMENT_DUPLICATE")
        if any(name not in PROCESS_ENVIRONMENT_ALLOWLIST for name in names):
            raise ContractError("PROCESS_ENVIRONMENT_NOT_ALLOWLISTED")
        if any("\x00" in name or "\x00" in value for name, value in self.environment):
            raise ContractError("PROCESS_ENVIRONMENT_INVALID")


@dataclass(frozen=True)
class PowerShellHostProfile:
    """Identity-bound host and versioned wrapper used by an owner-approved command."""

    host: PowerShellHost
    executable: Path
    wrapper: Path
    executable_sha256: str
    executable_version: str

    def validate(self) -> None:
        if not self.executable.is_absolute() or not self.executable.is_file():
            raise ContractError("POWERSHELL_EXECUTABLE_INVALID")
        if not self.wrapper.is_absolute() or not self.wrapper.is_file():
            raise ContractError("POWERSHELL_WRAPPER_INVALID")
        if self.wrapper.suffix.casefold() != ".ps1":
            raise ContractError("POWERSHELL_WRAPPER_NOT_VERSIONED_SCRIPT")
        expected_name = {
            PowerShellHost.WINDOWS_POWERSHELL_5_1: (
                "invoke-incident-command-windows-powershell-5.1-v1.ps1"
            ),
            PowerShellHost.POWERSHELL_7: "invoke-incident-command-powershell-7-v1.ps1",
        }[self.host]
        if self.wrapper.name != expected_name:
            raise ContractError("POWERSHELL_WRAPPER_PROFILE_MISMATCH")
        validate_sha256(self.executable_sha256)
        if not self.executable_version.strip():
            raise ContractError("POWERSHELL_VERSION_REQUIRED")
        expected_executable, expected_major = {
            PowerShellHost.WINDOWS_POWERSHELL_5_1: ("powershell.exe", "5"),
            PowerShellHost.POWERSHELL_7: ("pwsh.exe", "7"),
        }[self.host]
        if (
            self.executable.name.casefold() != expected_executable
            or self.executable_version.split(".", maxsplit=1)[0] != expected_major
        ):
            raise ContractError("POWERSHELL_HOST_IDENTITY_MISMATCH")


def build_powershell_process_request(
    profile: PowerShellHostProfile,
    *,
    request_path: Path,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
) -> ProcessRequest:
    """Build the immutable host argv; the request file owns the child command array."""
    profile.validate()
    if not request_path.is_absolute() or not request_path.is_file():
        raise ContractError("POWERSHELL_REQUEST_INVALID")
    request = ProcessRequest(
        argv=(
            str(profile.executable),
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(profile.wrapper),
            "-RequestPath",
            str(request_path),
        ),
        cwd=cwd,
        environment=tuple(sorted(environment.items(), key=lambda item: item[0].upper())),
        timeout_seconds=timeout_seconds,
        executable_sha256=profile.executable_sha256,
        executable_version=profile.executable_version,
    )
    request.validate()
    return request


class CancellationToken(Protocol):
    def is_cancelled(self) -> bool: ...


class CommandRunner(Protocol):
    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: int,
    ) -> ProcessResult: ...


def normalize_results(value: object) -> tuple[ResultCardinality, tuple[object, ...]]:
    """Normalize external zero/one/many values without scalar `.Count` assumptions."""
    if value is None:
        return ResultCardinality.ZERO, ()
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        items = tuple(value)
    else:
        items = (value,)
    cardinality = (
        ResultCardinality.ZERO
        if not items
        else ResultCardinality.ONE
        if len(items) == 1
        else ResultCardinality.MANY
    )
    return cardinality, items


def decode_utf8_output(value: bytes) -> str:
    """Accept UTF-8 with or without BOM while returning normalized BOM-free text."""
    if value.startswith(codecs.BOM_UTF8):
        value = value[len(codecs.BOM_UTF8) :]
    try:
        return value.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProcessOutcomeUncertain("PROCESS_OUTPUT_NOT_UTF8") from exc


def capture_process(
    arguments: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    executable_sha256: str | None = None,
    executable_version: str | None = None,
    progress: Callable[[str], None] | None = None,
    cancellation: CancellationToken | None = None,
) -> ProcessResult:
    """Execute an already-authorized argv without a shell or ambient environment."""
    if (
        not arguments
        or not Path(arguments[0]).is_absolute()
        or timeout_seconds <= 0
        or not cwd.is_absolute()
        or not cwd.is_dir()
        or any(not item or "\x00" in item for item in arguments)
    ):
        raise ContractError("PROCESS_ARGUMENT_BOUNDARY")
    if executable_sha256 is not None:
        validate_sha256(executable_sha256)
    if executable_version is not None and not executable_version.strip():
        raise ContractError("PROCESS_EXECUTABLE_VERSION_INVALID")
    environment_names = [name.upper() for name in environment]
    if (
        len(environment_names) != len(set(environment_names))
        or any(name not in PROCESS_ENVIRONMENT_ALLOWLIST for name in environment_names)
        or any("\x00" in value for value in environment.values())
    ):
        raise ContractError("PROCESS_ENVIRONMENT_NOT_ALLOWLISTED")
    chunks = [bytearray(), bytearray()]
    overflow = threading.Event()
    events: list[str] = []
    started = time.monotonic()

    def announce(event: str) -> None:
        events.append(event)
        if progress is not None:
            progress(event)

    announce(f"started deadline_seconds={timeout_seconds}")
    try:
        process = subprocess.Popen(  # noqa: S603
            tuple(arguments),
            cwd=cwd,
            env=dict(environment),
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
        readers = (
            threading.Thread(target=drain, args=(process.stdout, chunks[0]), daemon=True),
            threading.Thread(target=drain, args=(process.stderr, chunks[1]), daemon=True),
        )
        for reader in readers:
            reader.start()
        deadline = started + timeout_seconds
        classification: ProcessClassification | None = None
        while process.poll() is None:
            if cancellation is not None and cancellation.is_cancelled():
                classification = ProcessClassification.CANCELLED
                process.kill()
                break
            if time.monotonic() >= deadline:
                classification = ProcessClassification.TIMED_OUT
                process.kill()
                break
            try:
                process.wait(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                announce("progress running")
                continue
            except KeyboardInterrupt:
                classification = ProcessClassification.CANCELLED
                process.kill()
                break
        process.wait(timeout=10)
        for reader in readers:
            reader.join(timeout=10)
        if overflow.is_set() or any(reader.is_alive() for reader in readers):
            raise ProcessOutcomeUncertain("PROCESS_OUTPUT_LIMIT_OR_INCOMPLETE")
        elapsed = time.monotonic() - started
        if classification is not None:
            announce(classification.value.casefold())
        else:
            classification = (
                ProcessClassification.SUCCEEDED
                if process.returncode == 0
                else ProcessClassification.FAILED
            )
            announce(f"completed exit_code={process.returncode}")
        return ProcessResult(
            process.returncode
            if classification is ProcessClassification.SUCCEEDED
            else process.returncode or -1,
            decode_utf8_output(bytes(chunks[0])),
            decode_utf8_output(bytes(chunks[1])),
            elapsed,
            classification,
            executable_sha256,
            executable_version,
            tuple(events),
        )
    except subprocess.TimeoutExpired:
        raise ProcessOutcomeUncertain("PROCESS_TERMINATION_UNPROVEN") from None
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProcessOutcomeUncertain("PROCESS_COMPLETION_UNPROVEN") from exc
