"""Rollback behavior for immutable N and non-destructive state failures."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from enterprise_ai_platform.rag_rollback import identity as identity_module
from enterprise_ai_platform.rag_rollback import state as state_module
from enterprise_ai_platform.rag_rollback.errors import RollbackStateConflictError
from enterprise_ai_platform.rag_rollback.identity import validate_identity_pair

ROOT = Path(__file__).resolve().parents[2]
DESCRIPTORS = (
    ROOT / "configs/rag/versions/known-good-v2.json",
    ROOT / "configs/rag/versions/synthetic-regression-v2.json",
)
pytestmark = pytest.mark.skipif(
    not all(
        (ROOT / relative).is_file()
        for relative in ("reports/eval.json", "reports/eval-repeat.json")
    ),
    reason="ignored owner-local W3 evaluation reports are absent",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _isolate_state(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    known_good, regression = validate_identity_pair()
    (tmp_path / "reports").mkdir()
    monkeypatch.setattr(identity_module, "REPOSITORY_ROOT", tmp_path)
    monkeypatch.setattr(
        state_module,
        "load_identity",
        lambda alias: known_good if alias == "known-good" else regression,
    )


def test_rollback_restores_n_is_idempotent_and_never_changes_descriptors(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    descriptor_hashes = tuple(_sha256(path) for path in DESCRIPTORS)
    _isolate_state(monkeypatch, tmp_path)
    state_module.activate_identity("known-good", expected_current="absent")
    state_module.activate_identity(
        "synthetic-regression",
        expected_current="known-good",
    )
    restored = state_module.activate_identity(
        "known-good",
        expected_current="synthetic-regression",
    )
    repeated = state_module.activate_identity(
        "known-good",
        expected_current="synthetic-regression",
    )

    assert restored.status == "ACTIVATED"
    assert repeated.status == "ALREADY_ACTIVE"
    assert state_module.require_activation_state("known-good").generation == 3
    assert tuple(_sha256(path) for path in DESCRIPTORS) == descriptor_hashes


def test_failed_compare_and_swap_requires_forward_action_without_fallback(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _isolate_state(monkeypatch, tmp_path)
    state_module.activate_identity("known-good", expected_current="absent")
    before = state_module.read_activation_state()

    with pytest.raises(RollbackStateConflictError):
        state_module.activate_identity(
            "synthetic-regression",
            expected_current="synthetic-regression",
        )

    assert state_module.read_activation_state() == before
    assert state_module.require_activation_state("known-good") == before
