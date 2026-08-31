"""Integration proof for the complete local W4-11 control-plane composition."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from enterprise_ai_platform.release_rollback import state as state_module
from enterprise_ai_platform.release_rollback.service import (
    cleanup,
    rollback_release,
    smoke,
    verify_clean,
    verify_zero_residue,
)
from tests.fakes.release_rollback import (
    DeterministicReleaseProbe,
    isolate_release_runtime,
)


def test_release_lifecycle_composes_identity_state_probe_smoke_and_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    probe = DeterministicReleaseProbe()

    lifecycle = asyncio.run(rollback_release(probe))
    restored = state_module.require_active_state("w4-known-good-v1")

    assert lifecycle.status == "RESTORED_KNOWN_GOOD"
    assert lifecycle.regression.gate_status == "FAIL"
    assert lifecycle.rollback.rollback_status == "PASS"
    assert lifecycle.regression.generation == 2
    assert lifecycle.rollback.generation == restored.generation == 3
    assert restored.agent_route_allowed is False
    assert probe.candidate_calls == 1
    assert state_module.verify_runtime_inventory(require_complete=False) == 3

    smoke_report = asyncio.run(smoke(probe))
    clean = verify_clean()

    assert smoke_report.smoke_status == "PASS"
    assert probe.restored_calls == 1
    assert state_module.require_active_state(
        "w4-known-good-v1"
    ).agent_route_allowed
    assert clean.status == "CLEAN" and clean.approved_artifact_count == 4

    removed = cleanup(owner_output_captured=True)
    assert removed.status == "ZERO_RESIDUE"
    assert verify_zero_residue().unexpected_residue_count == 0
    assert not (tmp_path / state_module.RUNTIME_DIRECTORY).exists()
