"""Read-only structured cleanliness verification for W2-004."""

from __future__ import annotations

import json
import subprocess  # noqa: S404 - execution is restricted to a fixed read-only allowlist
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from pathlib import Path

PROJECT = "enterprise-ai-w2-004a"
PROJECT_LABEL = f"label=com.docker.compose.project={PROJECT}"
RUNNER_IMAGE_LABEL = "label=com.enterprise-ai.w2-004.role=local-retrieval-test-runner"
MODEL_CACHE = Path(r"E:\AI\.model-cache\enterprise_ai_platform\W2-002")
EXTERNAL_VENV = Path(r"E:\AI\.venvs\enterprise_ai_platform")
ALLOWED_EXCEL_LOCK = (
    "docs/governance/~$Enterprise_AI_Architecture_6_Week_Execution_Tracker_v1.3.4_repaired.xlsx"
)
APPROVED_CHANGED_PATHS = frozenset(
    {
        "Makefile",
        "docker-compose.w2-004.yml",
        "docker/local-retrieval-runner.Dockerfile",
        "docker/local-retrieval-runner.Dockerfile.dockerignore",
        "docker/local-retrieval-runner.requirements.txt",
        "feature-matrix.yaml",
        "src/enterprise_ai_platform/retrieval/__init__.py",
        "src/enterprise_ai_platform/retrieval/service.py",
        "tests/contract/test_retrieval_service.py",
        "tests/feature/test_feature_matrix.py",
        "tests/feature/test_local_retrieval.py",
        "tests/feature/test_w2_003_ingestion_contract.py",
        "tests/rollback/test_w2_004_local_rollback.py",
        "tests/security/test_w2_004_retrieval_security.py",
        "tests/teardown/test_w2_004_retrieval_cleanliness.py",
        "tests/unit/test_platformctl.py",
        "tests/unit/test_retrieval_service.py",
        "tests/unit/test_verify_w2_004_local.py",
        "tools/platformctl/validate.py",
        "tools/verify_w2_004_local.py",
    }
)


class State(StrEnum):
    REMOVED = "REMOVED"
    RETAINED = "RETAINED"
    NOT_RUN = "NOT_RUN"
    INDETERMINATE = "INDETERMINATE"
    PROHIBITED = "PROHIBITED"


@dataclass(frozen=True, slots=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    state: State
    details: dict[str, object]


CommandRunner = Callable[[Sequence[str]], CommandResult]

CONTAINER_COMMAND = (
    "docker",
    "ps",
    "-a",
    "--filter",
    PROJECT_LABEL,
    "--format",
    "{{.ID}}",
)
PROCESS_COMMAND = (
    "docker",
    "ps",
    "--filter",
    PROJECT_LABEL,
    "--format",
    "{{.ID}}",
)
VOLUME_COMMAND = (
    "docker",
    "volume",
    "ls",
    "--filter",
    PROJECT_LABEL,
    "--format",
    "{{.Name}}",
)
NETWORK_COMMAND = (
    "docker",
    "network",
    "ls",
    "--filter",
    PROJECT_LABEL,
    "--format",
    "{{.Name}}",
)
RUNNER_IMAGE_COMMAND = (
    "docker",
    "image",
    "ls",
    "--filter",
    RUNNER_IMAGE_LABEL,
    "--format",
    "{{.Repository}}:{{.Tag}}",
)
QDRANT_IMAGE_COMMAND = (
    "docker",
    "image",
    "inspect",
    "--format",
    "{{.Id}}|{{json .RepoDigests}}|{{.Size}}",
    (
        "qdrant/qdrant:v1.19.0-unprivileged@"
        "sha256:a0e04fe623cb064502cd869cefc1dc7ce359d8edd481063b5bd351c0a0a2c91e"
    ),
)
PYTHON_IMAGE_COMMAND = (
    "docker",
    "image",
    "inspect",
    "--format",
    "{{.Id}}|{{json .RepoDigests}}|{{.Size}}",
    (
        "python:3.13.7-slim-bookworm@"
        "sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d"
    ),
)
BUILD_CACHE_COMMAND = ("docker", "buildx", "du")
GIT_STATUS_COMMAND = (
    "git",
    "status",
    "--porcelain=v1",
    "--untracked-files=all",
)
GIT_IGNORED_COMMAND = (
    "git",
    "status",
    "--ignored",
    "--porcelain=v1",
    "--untracked-files=all",
)
READ_ONLY_COMMANDS = (
    CONTAINER_COMMAND,
    PROCESS_COMMAND,
    VOLUME_COMMAND,
    NETWORK_COMMAND,
    RUNNER_IMAGE_COMMAND,
    QDRANT_IMAGE_COMMAND,
    PYTHON_IMAGE_COMMAND,
    BUILD_CACHE_COMMAND,
    GIT_STATUS_COMMAND,
    GIT_IGNORED_COMMAND,
)


def run_command(command: Sequence[str]) -> CommandResult:
    """Run one fixed inventory command without invoking a shell."""

    normalized = tuple(command)
    if normalized not in READ_ONLY_COMMANDS:
        return CommandResult(returncode=126)
    try:
        completed = subprocess.run(  # noqa: S603 - fixed allowlist enforced above
            list(normalized),
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            shell=False,
        )
    except (OSError, subprocess.SubprocessError):
        return CommandResult(returncode=127)
    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr="",
    )


def _nonempty_lines(value: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def _status_lines(value: str) -> tuple[str, ...]:
    return tuple(line.rstrip() for line in value.splitlines() if line.strip())


def _absence_check(
    name: str,
    command: Sequence[str],
    runner: CommandRunner,
) -> CheckResult:
    result = runner(command)
    if result.returncode != 0:
        return CheckResult(name, State.INDETERMINATE, {"exit_code": result.returncode})
    entries = _nonempty_lines(result.stdout)
    return CheckResult(
        name,
        State.REMOVED if not entries else State.PROHIBITED,
        {"count": len(entries)},
    )


def _retained_image_check(
    name: str,
    command: Sequence[str],
    runner: CommandRunner,
) -> CheckResult:
    result = runner(command)
    if result.returncode != 0:
        return CheckResult(name, State.NOT_RUN, {"present": False})
    identities = _nonempty_lines(result.stdout)
    return CheckResult(
        name,
        State.RETAINED if identities else State.NOT_RUN,
        {"identity_digest_size": list(identities)},
    )


def _repository_artifacts(root: Path) -> tuple[str, ...]:
    forbidden_names = {
        ".coverage",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "__pycache__",
        "htmlcov",
    }
    findings: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.name in forbidden_names or (
            path.is_file() and path.suffix.casefold() in {".pyc", ".pyo"}
        ):
            findings.append(relative.as_posix())
    for relative_path in ("manifest", "manifests", "quarantine", ".model-cache"):
        candidate = root / relative_path
        if candidate.exists():
            findings.append(relative_path)
    return tuple(sorted(set(findings)))


def _git_path(line: str) -> str:
    path = line[3:].strip()
    if " -> " in path:
        return path.split(" -> ", maxsplit=1)[1]
    return path


def _git_status_check(runner: CommandRunner) -> CheckResult:
    result = runner(GIT_STATUS_COMMAND)
    if result.returncode != 0:
        return CheckResult(
            "unexpected_repository_changes",
            State.INDETERMINATE,
            {"exit_code": result.returncode},
        )
    unexpected = tuple(
        sorted(
            path
            for path in (_git_path(line) for line in _status_lines(result.stdout))
            if path not in APPROVED_CHANGED_PATHS and path != ALLOWED_EXCEL_LOCK
        )
    )
    return CheckResult(
        "unexpected_repository_changes",
        State.REMOVED if not unexpected else State.PROHIBITED,
        {"count": len(unexpected), "paths": list(unexpected)},
    )


def _ignored_files_check(runner: CommandRunner) -> CheckResult:
    result = runner(GIT_IGNORED_COMMAND)
    if result.returncode != 0:
        return CheckResult(
            "unexpected_ignored_files",
            State.INDETERMINATE,
            {"exit_code": result.returncode},
        )
    ignored = tuple(
        sorted(_git_path(line) for line in _status_lines(result.stdout) if line.startswith("!! "))
    )
    return CheckResult(
        "unexpected_ignored_files",
        State.REMOVED if not ignored else State.PROHIBITED,
        {"count": len(ignored), "paths": list(ignored)},
    )


def verify_cleanliness(
    *,
    repository_root: Path,
    model_cache: Path = MODEL_CACHE,
    external_venv: Path = EXTERNAL_VENV,
    runner: CommandRunner = run_command,
) -> tuple[CheckResult, ...]:
    """Return redacted W2-004 residue and retained-resource classifications."""

    containers = _absence_check("project_containers", CONTAINER_COMMAND, runner)
    volumes = _absence_check("project_volumes", VOLUME_COMMAND, runner)
    results = [
        containers,
        _absence_check("project_runtime_processes", PROCESS_COMMAND, runner),
        volumes,
        _absence_check("project_networks", NETWORK_COMMAND, runner),
        _absence_check("local_runner_image", RUNNER_IMAGE_COMMAND, runner),
        CheckResult(
            "task_collection_storage",
            State.REMOVED if volumes.state is State.REMOVED else State.INDETERMINATE,
            {"derived_from_absent_task_volume": volumes.state is State.REMOVED},
        ),
    ]
    repository_findings = _repository_artifacts(repository_root)
    results.extend(
        (
            CheckResult(
                "repository_caches_bytecode_and_task_paths",
                State.REMOVED if not repository_findings else State.PROHIBITED,
                {"count": len(repository_findings), "paths": list(repository_findings)},
            ),
            _git_status_check(runner),
            _ignored_files_check(runner),
            CheckResult(
                "external_w2_002_model_cache",
                State.PROHIBITED if model_cache.exists() else State.REMOVED,
                {"path": str(model_cache), "present": model_cache.exists()},
            ),
            CheckResult(
                "external_python_virtual_environment",
                State.RETAINED if external_venv.exists() else State.NOT_RUN,
                {"path": str(external_venv), "present": external_venv.exists()},
            ),
            _retained_image_check(
                "shared_qdrant_base_image",
                QDRANT_IMAGE_COMMAND,
                runner,
            ),
            _retained_image_check(
                "shared_python_base_image",
                PYTHON_IMAGE_COMMAND,
                runner,
            ),
        )
    )
    build_cache = runner(BUILD_CACHE_COMMAND)
    if build_cache.returncode != 0:
        results.append(
            CheckResult(
                "shared_buildkit_cache",
                State.INDETERMINATE,
                {"exit_code": build_cache.returncode},
            )
        )
    else:
        summary = "\n".join(_nonempty_lines(build_cache.stdout))[:4000]
        results.append(
            CheckResult(
                "shared_buildkit_cache",
                State.RETAINED if summary else State.NOT_RUN,
                {"inventory": summary},
            )
        )
    return tuple(results)


def exit_code(results: Sequence[CheckResult]) -> int:
    return int(any(result.state in {State.PROHIBITED, State.INDETERMINATE} for result in results))


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    results = verify_cleanliness(repository_root=root)
    code = exit_code(results)
    print(
        json.dumps(
            {
                "schema_version": "1.0",
                "task": "W2-004",
                "overall": "PASS" if code == 0 else "FAIL",
                "checks": [asdict(result) for result in results],
            },
            default=str,
            indent=2,
            sort_keys=True,
        )
    )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
