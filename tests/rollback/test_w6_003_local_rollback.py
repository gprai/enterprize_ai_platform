from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tests.fakes.release_rollback import (
    DeterministicReleaseProbe,
    isolate_release_runtime,
)

from enterprise_ai_platform.release_rollback import state as state_module
from enterprise_ai_platform.release_rollback.service import (
    cleanup,
    rollback_release,
    smoke,
    verify_clean,
)


def test_candidate_failure_restores_known_good_and_cleans_local_residue(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    probe = DeterministicReleaseProbe()

    rollback = asyncio.run(rollback_release(probe))
    restored_smoke = asyncio.run(smoke(probe))
    clean = verify_clean()

    assert rollback.status == "RESTORED_KNOWN_GOOD"
    assert rollback.regression.gate_status == "FAIL"
    assert rollback.rollback.rollback_status == "PASS"
    assert restored_smoke.smoke_status == "PASS"
    assert clean.unexpected_residue_count == 0
    assert state_module.require_active_state("w4-known-good-v1").agent_route_allowed is True

    residue = cleanup(owner_output_captured=True)
    assert residue.status == "ZERO_RESIDUE"
    assert list((tmp_path / "reports").iterdir()) == []
