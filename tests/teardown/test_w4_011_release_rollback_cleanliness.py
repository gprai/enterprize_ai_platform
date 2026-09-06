"""Cleanliness and immutable-input protection for W4-11 Column L."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from enterprise_ai_platform.release_rollback import state as state_module
from enterprise_ai_platform.release_rollback.identity import (
    APPROVED_ARTIFACT_PATHS,
    hash_file,
    load_release_descriptor,
)
from enterprise_ai_platform.release_rollback.service import (
    cleanup,
    rollback_release,
    smoke,
    verify_zero_residue,
)
from tests.fakes.release_rollback import (
    DeterministicReleaseProbe,
    isolate_release_runtime,
)

ROOT = Path(__file__).resolve().parents[2]


def test_column_l_created_no_runtime_release_or_temporary_residue() -> None:
    runtime = ROOT / state_module.RUNTIME_DIRECTORY
    assert not runtime.exists()
    assert tuple((ROOT / "reports").glob("w4-release/.*.tmp")) == ()


def test_ignore_boundary_is_exact_and_not_a_broad_reports_ignore() -> None:
    ignore_lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    expected = {
        "reports/w4-release/active.json",
        "reports/w4-release/regression.json",
        "reports/w4-release/rollback.json",
        "reports/w4-release/smoke.json",
        "reports/w4-release/activation.lock",
        "reports/w4-release/.active.json.*.tmp",
        "reports/w4-release/.regression.json.*.tmp",
        "reports/w4-release/.rollback.json.*.tmp",
        "reports/w4-release/.smoke.json.*.tmp",
    }
    assert expected.issubset(ignore_lines)
    assert "reports/" not in ignore_lines
    assert "reports/w4-release/" not in ignore_lines


def test_historical_descriptors_remain_byte_exact_and_internally_complete() -> None:
    descriptor = load_release_descriptor("w4-known-good-v1")
    assert tuple(item.path for item in descriptor.artifacts) == (APPROVED_ARTIFACT_PATHS)
    expected_descriptor_hashes = {
        "configs/releases/versions/w4-known-good-v1.json": (
            "149c80300928e2c04c03f53be694876679655f4f316722c4dbfa65b33a485f94"
        ),
        "configs/releases/versions/w4-synthetic-regression-v1.json": (
            "d8e65865c5564d9eccc57089564b17fb3f3b86ad46106143a091ef659d9571c3"
        ),
    }
    assert {
        path: hash_file(ROOT / path) for path in expected_descriptor_hashes
    } == expected_descriptor_hashes


def test_owner_captured_cleanup_removes_only_isolated_runtime_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    probe = DeterministicReleaseProbe()
    asyncio.run(rollback_release(probe))
    asyncio.run(smoke(probe))

    result = cleanup(owner_output_captured=True)

    assert result.status == "ZERO_RESIDUE"
    assert verify_zero_residue().approved_artifact_count == 0
    assert not (tmp_path / state_module.RUNTIME_DIRECTORY).exists()
    assert (tmp_path / "reports").is_dir()
