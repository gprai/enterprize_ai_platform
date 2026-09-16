"""Unit tests for atomic W5-004 operation and approval state."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from tools.platformctl.lifecycle_models import OperationLock, OperationPhase, PurgeItem
from tools.platformctl.operation_state import OperationLedger, OperationStateError


def test_durable_journal_failure_cannot_return_to_approved(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    ledger = OperationLedger(tmp_path / "ledger", repository)
    for phase in (OperationPhase.PREPARED, OperationPhase.REVIEW_FAILED):
        ledger.transition(
            "operation-one", phase, artifact_sha256=None, recorded_at="2026-09-08T00:00:00Z"
        )
    try:
        ledger.transition(
            "operation-one",
            OperationPhase.APPROVED,
            artifact_sha256="a" * 64,
            recorded_at="2026-09-08T00:01:00Z",
        )
    except OperationStateError:
        pass
    else:
        raise AssertionError("a failed operation was reapproved")
    assert len(ledger.journal("operation-one")) == 2


NOW = datetime(2026, 9, 8, 0, 10, tzinfo=UTC)


def lock() -> OperationLock:
    return OperationLock(
        schema_version="w5-004.lifecycle.v1",
        operation_id="operation-001",
        action="PLATFORM-APPLY",
        environment="sandbox",
        target="platform",
        artifact_sha256="a" * 64,
        created_at="2026-09-08T00:00:00Z",
        expires_at="2026-09-08T00:30:00Z",
    )


def test_operation_lock_is_mutually_exclusive(tmp_path: Path) -> None:
    ledger = OperationLedger(tmp_path / "ledger", Path.cwd())
    ledger.acquire(lock(), NOW)
    with pytest.raises(OperationStateError, match="already recorded"):
        ledger.acquire(lock(), NOW)
    ledger.release("operation-001")


def test_approval_consumption_is_one_time(tmp_path: Path) -> None:
    ledger = OperationLedger(tmp_path / "ledger", Path.cwd())
    assert not ledger.is_used("approval-001")
    ledger.consume("approval-001", "a" * 64, "2026-09-08T00:10:00Z")
    assert ledger.is_used("approval-001")
    with pytest.raises(ValueError, match="already been used"):
        ledger.consume("approval-001", "a" * 64, "2026-09-08T00:11:00Z")


def test_consumed_artifact_cannot_be_relabelled_with_another_approval(tmp_path: Path) -> None:
    ledger = OperationLedger(tmp_path / "ledger", Path.cwd())
    ledger.consume("approval-original", "a" * 64, "2026-09-08T00:10:00Z")
    with pytest.raises(ValueError, match="already been used"):
        ledger.consume("approval-renamed", "a" * 64, "2026-09-08T00:11:00Z")
    assert not ledger.is_used("approval-renamed")


@pytest.mark.parametrize("approval_id", ["../outside", "a/b", "a\\b", "name:stream", "."])
def test_approval_marker_rejects_path_components(tmp_path: Path, approval_id: str) -> None:
    ledger = OperationLedger(tmp_path / "ledger", Path.cwd())
    with pytest.raises(OperationStateError, match="OPERATION_ID_INVALID"):
        ledger.is_used(approval_id)
    with pytest.raises(OperationStateError, match="OPERATION_ID_INVALID"):
        ledger.consume(approval_id, "a" * 64, "2026-09-08T00:10:00Z")
    assert list((tmp_path / "ledger").iterdir()) == []


def executing_purge(tmp_path: Path) -> tuple[OperationLedger, SimpleNamespace]:
    ledger = OperationLedger(tmp_path / "ledger", Path.cwd())
    context = SimpleNamespace(
        package=SimpleNamespace(
            operation_id="operation-001",
            artifact=SimpleNamespace(sha256="a" * 64),
        ),
        approval=SimpleNamespace(approval_id="approval-001"),
    )
    for phase in (
        OperationPhase.PREPARED,
        OperationPhase.ELIGIBLE_FOR_REVIEW,
        OperationPhase.APPROVED,
    ):
        ledger.transition(
            "operation-001",
            phase,
            artifact_sha256="a" * 64,
            recorded_at="2026-09-08T00:10:00Z",
            approval_id="approval-001",
        )
    ledger.consume("approval-001", "a" * 64, "2026-09-08T00:10:00Z")
    ledger.transition(
        "operation-001",
        OperationPhase.EXECUTION_STARTED,
        artifact_sha256="a" * 64,
        recorded_at="2026-09-08T00:10:00Z",
        approval_id="approval-001",
    )
    return ledger, context


def test_purge_batch_is_consumed_once_before_dispatch(tmp_path: Path) -> None:
    ledger, context = executing_purge(tmp_path)
    item = PurgeItem("OBJECT_VERSION", "synthetic-object", "version-one")
    ledger.start_purge_batch(context, 1, item)
    ledger.require_purge_batch(context, 1, item)
    with pytest.raises(OperationStateError, match="ALREADY_DISPATCHED"):
        ledger.require_purge_batch(context, 1, item)
    ledger.complete_purge_batch(context, 1, item)
    second = PurgeItem("DELETE_MARKER", "synthetic-object", "version-two")
    ledger.start_purge_batch(context, 2, second)
    ledger.require_purge_batch(context, 2, second)
    ledger.complete_purge_batch(context, 2, second)


def test_purge_predecessor_replacement_blocks_next_batch(tmp_path: Path) -> None:
    ledger, context = executing_purge(tmp_path)
    item = PurgeItem("OBJECT_VERSION", "synthetic-object", "version-one")
    ledger.start_purge_batch(context, 1, item)
    ledger.require_purge_batch(context, 1, item)
    ledger.complete_purge_batch(context, 1, item)
    completed = tmp_path / "ledger/batches/operation-001/000001.complete.json"
    completed.write_text("{}\n", encoding="utf-8")
    with pytest.raises(OperationStateError, match="MALFORMED"):
        ledger.start_purge_batch(
            context,
            2,
            PurgeItem("OBJECT_VERSION", "second-object", "version-two"),
        )
    assert not (completed.parent / "000002.started.json").exists()


def test_journaled_execution_lock_cannot_release_before_verification(tmp_path: Path) -> None:
    ledger, _ = executing_purge(tmp_path)
    ledger.acquire(lock(), NOW)
    with pytest.raises(OperationStateError):
        ledger.release("operation-001")
    with pytest.raises(OperationStateError):
        ledger.acquire(lock(), NOW)
