"""Unit coverage for W3-004 locking, CAS, atomicity and cleanup."""

from __future__ import annotations

from pathlib import Path

import pytest

from enterprise_ai_platform.rag_rollback import identity as identity_module
from enterprise_ai_platform.rag_rollback import state as state_module
from enterprise_ai_platform.rag_rollback.errors import (
    RollbackArtifactExistsError,
    RollbackCleanupError,
    RollbackLockError,
    RollbackStateConflictError,
    RollbackStateError,
)
from enterprise_ai_platform.rag_rollback.identity import validate_identity_pair

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    not all(
        (ROOT / relative).is_file()
        for relative in ("reports/eval.json", "reports/eval-repeat.json")
    ),
    reason="ignored owner-local W3 evaluation reports are absent",
)


def _isolate_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    known_good, regression = validate_identity_pair()
    (tmp_path / "reports").mkdir()
    monkeypatch.setattr(identity_module, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        state_module,
        "load_identity",
        lambda alias: known_good if alias == "known-good" else regression,
    )


def test_activation_is_atomic_idempotent_and_generation_checked(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_state(monkeypatch, tmp_path)

    initial = state_module.activate_identity("known-good", expected_current="absent")
    repeated = state_module.activate_identity("known-good", expected_current="absent")
    regression = state_module.activate_identity(
        "synthetic-regression", expected_current="known-good"
    )
    restored = state_module.activate_identity("known-good", expected_current="synthetic-regression")

    assert initial.status == "ACTIVATED" and initial.generation == 1
    assert repeated.status == "ALREADY_ACTIVE" and repeated.generation == 1
    assert regression.generation == 2
    assert restored.generation == 3
    assert state_module.require_activation_state("known-good").generation == 3
    assert not (tmp_path / state_module.ACTIVATION_LOCK_PATH).exists()


def test_wrong_expected_current_and_contended_lock_do_not_change_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_state(monkeypatch, tmp_path)
    state_module.activate_identity("known-good", expected_current="absent")
    before = state_module.read_activation_state()

    with pytest.raises(RollbackStateConflictError):
        state_module.activate_identity(
            "synthetic-regression",
            expected_current="absent",
        )
    assert state_module.read_activation_state() == before

    lock = tmp_path / state_module.ACTIVATION_LOCK_PATH
    lock.write_text("controlled-lock\n", encoding="utf-8")
    with pytest.raises(RollbackLockError):
        state_module.activate_identity(
            "synthetic-regression",
            expected_current="known-good",
        )
    assert state_module.read_activation_state() == before


def test_atomic_replace_failure_removes_temporary_sibling(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_state(monkeypatch, tmp_path)

    def fail_replace(source: Path, target: Path) -> None:
        del source, target
        raise OSError

    monkeypatch.setattr(state_module.os, "replace", fail_replace)
    with pytest.raises(RollbackStateError):
        state_module.activate_identity("known-good", expected_current="absent")

    runtime = tmp_path / state_module.RUNTIME_DIRECTORY
    assert not (runtime / "active.json").exists()
    assert tuple(runtime.glob(".active.json.*.tmp")) == ()
    assert not (runtime / "activation.lock").exists()


def test_reports_are_no_overwrite_and_cleanup_requires_external_archive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_state(monkeypatch, tmp_path)
    state_module.activate_identity("known-good", expected_current="absent")
    state = state_module.require_activation_state("known-good")
    for path in (
        state_module.REGRESSION_REPORT_PATH,
        state_module.RESTORED_REPORT_PATH,
        state_module.ROLLBACK_RECORD_PATH,
    ):
        state_module.publish_artifact(path, b"{}\n", expected_state=state)
    with pytest.raises(RollbackArtifactExistsError):
        state_module.publish_artifact(
            state_module.REGRESSION_REPORT_PATH,
            b"replacement\n",
            expected_state=state,
        )

    assert state_module.verify_runtime_inventory(require_complete=True) == 4
    with pytest.raises(RollbackCleanupError):
        state_module.cleanup_complete_drill(external_archive_verified=False)
    state_module.cleanup_complete_drill(external_archive_verified=True)
    state_module.verify_zero_residue()
    assert not (tmp_path / state_module.RUNTIME_DIRECTORY).exists()


def test_archived_partial_failure_evidence_can_reach_zero_residue(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_state(monkeypatch, tmp_path)
    state_module.activate_identity("known-good", expected_current="absent")
    state = state_module.require_activation_state("known-good")
    state_module.publish_artifact(
        state_module.REGRESSION_REPORT_PATH,
        b"controlled-failure\n",
        expected_state=state,
    )

    with pytest.raises(RollbackCleanupError):
        state_module.cleanup_complete_drill(external_archive_verified=False)
    state_module.cleanup_complete_drill(external_archive_verified=True)
    state_module.verify_zero_residue()
