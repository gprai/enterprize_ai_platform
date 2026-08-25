"""Unit tests for the read-only W2-004 cleanliness verifier."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from tools.verify_w2_004_local import (
    BUILD_CACHE_COMMAND,
    CONTAINER_COMMAND,
    GIT_IGNORED_COMMAND,
    GIT_STATUS_COMMAND,
    NETWORK_COMMAND,
    PROCESS_COMMAND,
    PYTHON_IMAGE_COMMAND,
    QDRANT_IMAGE_COMMAND,
    READ_ONLY_COMMANDS,
    RUNNER_IMAGE_COMMAND,
    VOLUME_COMMAND,
    CommandResult,
    State,
    exit_code,
    verify_cleanliness,
)


class FakeRunner:
    def __init__(self, results: dict[tuple[str, ...], CommandResult]) -> None:
        self._results = results
        self.commands: list[tuple[str, ...]] = []

    def __call__(self, command: Sequence[str]) -> CommandResult:
        normalized = tuple(command)
        self.commands.append(normalized)
        return self._results.get(normalized, CommandResult(returncode=127))


def clean_results() -> dict[tuple[str, ...], CommandResult]:
    return {
        CONTAINER_COMMAND: CommandResult(0),
        PROCESS_COMMAND: CommandResult(0),
        VOLUME_COMMAND: CommandResult(0),
        NETWORK_COMMAND: CommandResult(0),
        RUNNER_IMAGE_COMMAND: CommandResult(0),
        QDRANT_IMAGE_COMMAND: CommandResult(
            0,
            "sha256:qdrant|[qdrant@sha256:index]|100\n",
        ),
        PYTHON_IMAGE_COMMAND: CommandResult(
            0,
            "sha256:python|[python@sha256:index]|200\n",
        ),
        BUILD_CACHE_COMMAND: CommandResult(0, "ID RECLAIMABLE SIZE\ncache false 1GB\n"),
        GIT_STATUS_COMMAND: CommandResult(
            0,
            " M Makefile\n"
            "?? tools/verify_w2_004_local.py\n"
            "?? docs/governance/"
            "~$Enterprise_AI_Architecture_6_Week_Execution_Tracker_"
            "v1.3.4_repaired.xlsx\n",
        ),
        GIT_IGNORED_COMMAND: CommandResult(0),
    }


def by_name(results):  # type: ignore[no-untyped-def]
    return {result.name: result for result in results}


def test_clean_inventory_passes_and_records_retained_shared_resources(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    virtual_environment = tmp_path / "external-venv"
    virtual_environment.mkdir()
    runner = FakeRunner(clean_results())

    results = verify_cleanliness(
        repository_root=repository,
        model_cache=tmp_path / "removed-model-cache",
        external_venv=virtual_environment,
        runner=runner,
    )
    checks = by_name(results)

    assert exit_code(results) == 0
    assert checks["project_containers"].state is State.REMOVED
    assert checks["project_runtime_processes"].state is State.REMOVED
    assert checks["task_collection_storage"].state is State.REMOVED
    assert checks["external_python_virtual_environment"].state is State.RETAINED
    assert checks["shared_qdrant_base_image"].state is State.RETAINED
    assert checks["shared_buildkit_cache"].state is State.RETAINED
    assert set(runner.commands) == set(READ_ONLY_COMMANDS)


def test_prohibited_residue_returns_nonzero_without_cleanup(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".pytest_cache").mkdir()
    model_cache = tmp_path / "model-cache"
    model_cache.mkdir()
    inventory = clean_results()
    inventory[CONTAINER_COMMAND] = CommandResult(0, "container-id\n")
    inventory[RUNNER_IMAGE_COMMAND] = CommandResult(0, "runner:latest\n")
    inventory[GIT_IGNORED_COMMAND] = CommandResult(0, "!! unexpected-local-file\n")

    results = verify_cleanliness(
        repository_root=repository,
        model_cache=model_cache,
        external_venv=tmp_path / "absent-venv",
        runner=FakeRunner(inventory),
    )
    checks = by_name(results)

    assert exit_code(results) == 1
    assert checks["project_containers"].state is State.PROHIBITED
    assert checks["local_runner_image"].state is State.PROHIBITED
    assert checks["repository_caches_bytecode_and_task_paths"].state is State.PROHIBITED
    assert checks["unexpected_ignored_files"].state is State.PROHIBITED
    assert checks["external_w2_002_model_cache"].state is State.PROHIBITED


def test_indeterminate_inventory_returns_nonzero(tmp_path: Path) -> None:
    inventory = clean_results()
    inventory[NETWORK_COMMAND] = CommandResult(125)
    results = verify_cleanliness(
        repository_root=tmp_path,
        model_cache=tmp_path / "absent-cache",
        external_venv=tmp_path / "absent-venv",
        runner=FakeRunner(inventory),
    )

    assert exit_code(results) == 1
    assert by_name(results)["project_networks"].state is State.INDETERMINATE


def test_inventory_commands_are_fixed_read_only_and_never_use_a_shell() -> None:
    forbidden = {"build", "create", "delete", "down", "prune", "rm", "stop", "up"}
    for command in READ_ONLY_COMMANDS:
        assert command
        assert not forbidden.intersection(part.casefold() for part in command)
