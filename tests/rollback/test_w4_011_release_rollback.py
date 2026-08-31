"""Failure-path proof that W4-11 never performs automatic fallback."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from tests.fakes.release_rollback import (
    DeterministicReleaseProbe,
    isolate_release_runtime,
)

from enterprise_ai_platform.release_rollback import state as state_module
from enterprise_ai_platform.release_rollback.errors import (
    ReleaseProbeError,
    ReleaseStateError,
)
from enterprise_ai_platform.release_rollback.service import (
    rollback_release,
    smoke,
)


def test_probe_failure_preserves_failed_candidate_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    probe = DeterministicReleaseProbe(candidate=ReleaseProbeError())

    with pytest.raises(ReleaseProbeError):
        asyncio.run(rollback_release(probe))

    active = state_module.require_active_state("w4-synthetic-regression-v1")
    assert active.agent_route_allowed is False
    assert state_module.verify_runtime_inventory(require_complete=False) == 1
    assert not (tmp_path / state_module.ROLLBACK_REPORT_PATH).exists()


def test_atomic_restore_failure_keeps_candidate_and_failure_report(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    original = state_module._atomic_replace_state

    def fail_only_restore(state: state_module.ActiveReleaseState) -> None:
        if state.active_release == "w4-known-good-v1" and state.generation > 1:
            raise ReleaseStateError
        original(state)

    monkeypatch.setattr(state_module, "_atomic_replace_state", fail_only_restore)
    with pytest.raises(ReleaseStateError):
        asyncio.run(rollback_release(DeterministicReleaseProbe()))

    active = state_module.require_active_state("w4-synthetic-regression-v1")
    assert active.agent_route_allowed is False
    assert (tmp_path / state_module.REGRESSION_REPORT_PATH).is_file()
    assert not (tmp_path / state_module.ROLLBACK_REPORT_PATH).exists()


def test_failed_restored_smoke_keeps_agent_latch_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    asyncio.run(rollback_release(DeterministicReleaseProbe()))

    failing = DeterministicReleaseProbe(restored=ReleaseProbeError())
    with pytest.raises(ReleaseProbeError):
        asyncio.run(smoke(failing))

    active = state_module.require_active_state("w4-known-good-v1")
    assert active.agent_route_allowed is False
    assert not (tmp_path / state_module.SMOKE_REPORT_PATH).exists()
