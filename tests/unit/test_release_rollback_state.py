"""Unit coverage for W4-11 locking, CAS, atomicity and latch behavior."""

from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.release_rollback import state as state_module
from enterprise_ai_platform.release_rollback.errors import (
    ReleaseArtifactExistsError,
    ReleaseLockError,
    ReleaseStateConflictError,
    ReleaseStateError,
)
from enterprise_ai_platform.release_rollback.identity import (
    APPROVED_COMPOSITION_SHA256,
    descriptor_sha256,
    load_release_descriptor,
)
from enterprise_ai_platform.release_rollback.models import (
    APPROVED_SMOKE_GATES,
    SmokeReport,
)
from tests.fakes.release_rollback import (
    isolate_release_runtime,
    restored_probe_result,
)


def test_activation_is_atomic_idempotent_and_generation_checked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)

    initial = state_module.activate_release("w4-known-good-v1", expected_current="absent")
    repeated = state_module.activate_release("w4-known-good-v1", expected_current="absent")
    candidate = state_module.activate_release(
        "w4-synthetic-regression-v1",
        expected_current="w4-known-good-v1",
    )
    restored = state_module.activate_release(
        "w4-known-good-v1",
        expected_current="w4-synthetic-regression-v1",
    )

    assert initial.status == "ACTIVATED" and initial.generation == 1
    assert repeated.status == "ALREADY_ACTIVE" and repeated.generation == 1
    assert candidate.generation == 2 and not candidate.agent_route_allowed
    assert restored.generation == 3 and not restored.agent_route_allowed
    assert not (tmp_path / state_module.ACTIVATION_LOCK_PATH).exists()


def test_wrong_expected_current_and_bounded_lock_leave_state_unchanged(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    state_module.activate_release("w4-known-good-v1", expected_current="absent")
    before = state_module.read_active_state()
    with pytest.raises(ReleaseStateConflictError):
        state_module.activate_release(
            "w4-synthetic-regression-v1",
            expected_current="absent",
        )

    lock = tmp_path / state_module.ACTIVATION_LOCK_PATH
    lock.write_text("controlled-lock\n", encoding="utf-8")
    times = iter((0.0, 1.0))
    monkeypatch.setattr(state_module.time, "monotonic", lambda: next(times))
    monkeypatch.setattr(state_module.time, "sleep", lambda _seconds: None)
    with pytest.raises(ReleaseLockError):
        state_module.activate_release(
            "w4-synthetic-regression-v1",
            expected_current="w4-known-good-v1",
        )
    assert state_module.read_active_state() == before


def test_atomic_replace_failure_removes_temporary_sibling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)

    def fail_replace(source: Path, target: Path) -> None:
        del source, target
        raise OSError

    monkeypatch.setattr(state_module.os, "replace", fail_replace)
    with pytest.raises(ReleaseStateError):
        state_module.activate_release("w4-known-good-v1", expected_current="absent")
    runtime = tmp_path / state_module.RUNTIME_DIRECTORY
    assert not (runtime / "active.json").exists()
    assert tuple(runtime.glob(".active.json.*.tmp")) == ()
    assert not (runtime / "activation.lock").exists()


def test_report_is_no_overwrite_and_smoke_atomically_enables_latch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    isolate_release_runtime(monkeypatch, tmp_path)
    state_module.activate_release("w4-known-good-v1", expected_current="absent")
    state = state_module.require_active_state("w4-known-good-v1")
    descriptor = load_release_descriptor("w4-known-good-v1")
    report = SmokeReport(
        schema_version="w4-011.smoke-report.v1",
        task_id="W4-ROLLBACK-001",
        release_version="w4-known-good-v1",
        descriptor_sha256=descriptor_sha256(descriptor),
        composition_sha256=APPROVED_COMPOSITION_SHA256,
        generation=state.generation,
        smoke_duration_ms=1,
        passed_gates=APPROVED_SMOKE_GATES,
        restored_probe=restored_probe_result(),
        smoke_status="PASS",
        agent_route_allowed_after_publish=True,
        network_activity=False,
    )

    enabled = state_module.publish_smoke_and_enable(
        report,
        expected_state=state,
    )
    assert enabled.agent_route_allowed is True
    assert state_module.read_active_state() == enabled
    with pytest.raises(ReleaseStateConflictError):
        state_module.publish_smoke_and_enable(report, expected_state=state)
    with pytest.raises(ReleaseArtifactExistsError):
        state_module.publish_report(
            state_module.SMOKE_REPORT_PATH,
            report,
            expected_state=enabled,
        )
