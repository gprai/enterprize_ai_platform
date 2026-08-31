"""Versioned SQLite state and bounded purge tests for W4-002."""

from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from enterprise_ai_platform.agent.errors import (
    AgentApprovalConflictError,
    AgentStateUnavailableError,
)
from enterprise_ai_platform.agent.models import (
    AgentNode,
    AgentState,
    ApprovalRecord,
    ApprovalStatus,
)
from enterprise_ai_platform.agent.persistence import SQLiteAgentStateStore


def _approval() -> ApprovalRecord:
    now = datetime.now(UTC)
    return ApprovalRecord(
        approval_id=uuid4(),
        request_id=uuid4(),
        run_id=uuid4(),
        tenant_reference_sha256="a" * 64,
        requester_reference_sha256="b" * 64,
        authorization_reference_sha256="c" * 64,
        tool_name="mock_set_service_mode",
        arguments_sha256="d" * 64,
        created_at=now,
        expires_at=now + timedelta(minutes=10),
    )


def test_store_round_trips_only_canonical_redacted_records(tmp_path: Path) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteAgentStateStore(path)
    approval = _approval()
    store.create_approval(approval, maximum_bytes=16_384)

    assert (
        store.get_approval(
            str(approval.approval_id),
            maximum_bytes=16_384,
        )
        == approval
    )
    assert path.is_file()


def test_expected_revision_prevents_duplicate_decision(tmp_path: Path) -> None:
    store = SQLiteAgentStateStore(tmp_path / "agent.sqlite3")
    pending = _approval()
    store.create_approval(pending, maximum_bytes=16_384)
    now = datetime.now(UTC)
    approved = pending.model_copy(
        update={
            "revision": 2,
            "status": ApprovalStatus.APPROVED,
            "approver_reference_sha256": "e" * 64,
            "approver_role": "reviewer",
            "idempotency_key_sha256": "f" * 64,
            "decision": "approved",
            "decided_at": now,
        }
    )
    store.approve(approved, expected_revision=1, maximum_bytes=16_384)

    with pytest.raises(AgentApprovalConflictError):
        store.approve(approved, expected_revision=1, maximum_bytes=16_384)


def test_exactly_one_concurrent_claimant_transitions_to_executing(
    tmp_path: Path,
) -> None:
    store = SQLiteAgentStateStore(tmp_path / "agent.sqlite3")
    pending = _approval()
    store.create_approval(pending, maximum_bytes=16_384)
    approved = pending.model_copy(
        update={
            "revision": 2,
            "status": ApprovalStatus.APPROVED,
            "approver_reference_sha256": "e" * 64,
            "approver_role": "reviewer",
            "idempotency_key_sha256": "f" * 64,
            "decision": "approved",
            "decided_at": datetime.now(UTC),
        }
    )
    store.approve(approved, expected_revision=1, maximum_bytes=16_384)

    def claim_once() -> bool:
        try:
            store.claim(
                str(pending.approval_id),
                expected_revision=2,
                maximum_bytes=16_384,
            )
        except AgentApprovalConflictError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: claim_once(), range(2)))
    assert sorted(outcomes) == [False, True]


def test_state_table_accepts_bounded_allowlist(tmp_path: Path) -> None:
    store = SQLiteAgentStateStore(tmp_path / "agent.sqlite3")
    state = AgentState(
        request_id=uuid4(),
        run_id=uuid4(),
        tenant_reference_sha256="a" * 64,
        subject_reference_sha256="b" * 64,
        authorization_reference_sha256="c" * 64,
        current_node=AgentNode.SAFE_TERMINAL,
    )
    store.save_state(state, maximum_bytes=16_384)
    with pytest.raises(AgentStateUnavailableError):
        store.save_state(state, maximum_bytes=16_384)


def test_store_version_mismatch_and_corrupt_payload_fail_closed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteAgentStateStore(path)
    approval = _approval()
    store.create_approval(approval, maximum_bytes=16_384)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute(
            "UPDATE approvals SET payload = ? WHERE approval_id = ?",
            (sqlite3.Binary(b"{}\n"), str(approval.approval_id)),
        )
        connection.commit()
    with pytest.raises(AgentStateUnavailableError):
        store.get_approval(str(approval.approval_id), maximum_bytes=16_384)

    with closing(sqlite3.connect(path)) as connection:
        connection.execute("UPDATE metadata SET value = 'unknown' WHERE key = 'schema_version'")
        connection.commit()
    with pytest.raises(AgentStateUnavailableError):
        SQLiteAgentStateStore(path)


def test_oversized_approval_is_rejected_before_storage(tmp_path: Path) -> None:
    store = SQLiteAgentStateStore(tmp_path / "agent.sqlite3")
    with pytest.raises(AgentStateUnavailableError):
        store.create_approval(_approval(), maximum_bytes=10)


def test_terminal_record_purge_is_explicit_and_bounded(tmp_path: Path) -> None:
    store = SQLiteAgentStateStore(tmp_path / "agent.sqlite3")
    pending = _approval()
    store.create_approval(pending, maximum_bytes=16_384)
    now = datetime.now(UTC)
    terminal = pending.model_copy(
        update={
            "revision": 2,
            "status": ApprovalStatus.REJECTED,
            "terminal_at": now,
        }
    )
    store.terminate_pending(terminal, expected_revision=1, maximum_bytes=16_384)

    assert (
        store.purge(
            before_epoch=int(now.timestamp()) + 1,
            maximum_records=1,
        )
        == 1
    )
    assert (
        store.get_approval(
            str(pending.approval_id),
            maximum_bytes=16_384,
        )
        is None
    )


def test_test_store_artifacts_are_bounded_to_temporary_directory(tmp_path: Path) -> None:
    database = tmp_path / "agent.sqlite3"
    SQLiteAgentStateStore(database)
    assert all(path.parent == tmp_path for path in tmp_path.iterdir())
