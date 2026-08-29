"""Standard-library SQLite store for redacted W4-002 state and approvals."""

from __future__ import annotations

import sqlite3
from contextlib import closing
from pathlib import Path

from .errors import AgentApprovalConflictError, AgentStateUnavailableError
from .models import (
    AGENT_STORE_SCHEMA_VERSION,
    AgentState,
    ApprovalRecord,
    ApprovalStatus,
)
from .serialization import canonical_bytes, load_canonical_model


class SQLiteAgentStateStore:
    """Small local store with version checks and atomic expected-state updates."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ValueError("agent store path must be absolute")
        self.path = path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with closing(self._connect()) as connection:
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS metadata "
                    "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS agent_states "
                    "(run_id TEXT PRIMARY KEY, revision INTEGER NOT NULL, "
                    "payload BLOB NOT NULL)"
                )
                connection.execute(
                    "CREATE TABLE IF NOT EXISTS approvals "
                    "(approval_id TEXT PRIMARY KEY, status TEXT NOT NULL, "
                    "revision INTEGER NOT NULL, expires_epoch INTEGER NOT NULL, "
                    "terminal_epoch INTEGER, idempotency_sha256 TEXT, "
                    "payload BLOB NOT NULL)"
                )
                connection.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS approvals_idempotency "
                    "ON approvals(idempotency_sha256) "
                    "WHERE idempotency_sha256 IS NOT NULL"
                )
                existing = connection.execute(
                    "SELECT value FROM metadata WHERE key = 'schema_version'"
                ).fetchone()
                if existing is None:
                    connection.execute(
                        "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                        (AGENT_STORE_SCHEMA_VERSION,),
                    )
                elif existing[0] != AGENT_STORE_SCHEMA_VERSION:
                    raise AgentStateUnavailableError
        except AgentStateUnavailableError:
            raise
        except (OSError, sqlite3.Error):
            raise AgentStateUnavailableError from None

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                self.path,
                timeout=1.0,
                isolation_level=None,
            )
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 1000")
            return connection
        except sqlite3.Error:
            raise AgentStateUnavailableError from None

    def _verify_version(self, connection: sqlite3.Connection) -> None:
        try:
            row = connection.execute(
                "SELECT value FROM metadata WHERE key = 'schema_version'"
            ).fetchone()
        except sqlite3.Error:
            raise AgentStateUnavailableError from None
        if row is None or row[0] != AGENT_STORE_SCHEMA_VERSION:
            raise AgentStateUnavailableError

    def save_state(self, state: AgentState, *, maximum_bytes: int) -> None:
        state = AgentState.model_validate(state.model_dump(mode="python"), strict=True)
        payload = canonical_bytes(state)
        if len(payload) > maximum_bytes:
            raise AgentStateUnavailableError
        try:
            with closing(self._connect()) as connection:
                self._verify_version(connection)
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "INSERT INTO agent_states(run_id, revision, payload) VALUES(?, ?, ?) "
                    "ON CONFLICT(run_id) DO UPDATE SET revision=excluded.revision, "
                    "payload=excluded.payload WHERE excluded.revision > agent_states.revision",
                    (str(state.run_id), state.revision, payload),
                )
                if cursor.rowcount != 1:
                    connection.execute("ROLLBACK")
                    raise AgentStateUnavailableError
                connection.execute("COMMIT")
        except AgentStateUnavailableError:
            raise
        except sqlite3.Error:
            raise AgentStateUnavailableError from None

    def create_approval(
        self,
        record: ApprovalRecord,
        *,
        maximum_bytes: int,
    ) -> None:
        record = ApprovalRecord.model_validate(
            record.model_dump(mode="python"),
            strict=True,
        )
        if record.status is not ApprovalStatus.PENDING:
            raise AgentApprovalConflictError
        payload = canonical_bytes(record)
        if len(payload) > maximum_bytes:
            raise AgentStateUnavailableError
        try:
            with closing(self._connect()) as connection:
                self._verify_version(connection)
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO approvals(approval_id, status, revision, expires_epoch, "
                    "terminal_epoch, idempotency_sha256, payload) "
                    "VALUES(?, ?, ?, ?, NULL, NULL, ?)",
                    (
                        str(record.approval_id),
                        record.status.value,
                        record.revision,
                        int(record.expires_at.timestamp()),
                        payload,
                    ),
                )
                connection.execute("COMMIT")
        except sqlite3.IntegrityError:
            raise AgentApprovalConflictError from None
        except AgentStateUnavailableError:
            raise
        except sqlite3.Error:
            raise AgentStateUnavailableError from None

    def get_approval(
        self,
        approval_id: str,
        *,
        maximum_bytes: int,
    ) -> ApprovalRecord | None:
        try:
            with closing(self._connect()) as connection:
                self._verify_version(connection)
                row = connection.execute(
                    "SELECT payload FROM approvals WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
        except AgentStateUnavailableError:
            raise
        except sqlite3.Error:
            raise AgentStateUnavailableError from None
        if row is None:
            return None
        payload = row[0]
        if not isinstance(payload, bytes):
            raise AgentStateUnavailableError
        return load_canonical_model(
            ApprovalRecord,
            payload,
            maximum_bytes=maximum_bytes,
        )

    def _replace(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        expected_status: ApprovalStatus,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        record = ApprovalRecord.model_validate(
            record.model_dump(mode="python"),
            strict=True,
        )
        if record.revision != expected_revision + 1:
            raise AgentApprovalConflictError
        payload = canonical_bytes(record)
        if len(payload) > maximum_bytes:
            raise AgentStateUnavailableError
        terminal_epoch = (
            None if record.terminal_at is None else int(record.terminal_at.timestamp())
        )
        try:
            with closing(self._connect()) as connection:
                self._verify_version(connection)
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute(
                    "UPDATE approvals SET status=?, revision=?, expires_epoch=?, "
                    "terminal_epoch=?, idempotency_sha256=?, payload=? "
                    "WHERE approval_id=? AND revision=? "
                    "AND status=?",
                    (
                        record.status.value,
                        record.revision,
                        int(record.expires_at.timestamp()),
                        terminal_epoch,
                        record.idempotency_key_sha256,
                        payload,
                        str(record.approval_id),
                        expected_revision,
                        expected_status.value,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.execute("ROLLBACK")
                    raise AgentApprovalConflictError
                connection.execute("COMMIT")
        except AgentApprovalConflictError:
            raise
        except sqlite3.IntegrityError:
            raise AgentApprovalConflictError from None
        except AgentStateUnavailableError:
            raise
        except sqlite3.Error:
            raise AgentStateUnavailableError from None
        return record

    def approve(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        if record.status is not ApprovalStatus.APPROVED:
            raise AgentApprovalConflictError
        return self._replace(
            record,
            expected_revision=expected_revision,
            expected_status=ApprovalStatus.PENDING,
            maximum_bytes=maximum_bytes,
        )

    def claim(
        self,
        approval_id: str,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        current = self.get_approval(approval_id, maximum_bytes=maximum_bytes)
        if current is None or current.status is not ApprovalStatus.APPROVED:
            raise AgentApprovalConflictError
        values = current.model_dump(mode="python")
        values.update(
            status=ApprovalStatus.EXECUTING,
            revision=current.revision + 1,
        )
        executing = ApprovalRecord.model_validate(values, strict=True)
        return self._replace(
            executing,
            expected_revision=expected_revision,
            expected_status=ApprovalStatus.APPROVED,
            maximum_bytes=maximum_bytes,
        )

    def terminate_pending(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        if record.status not in {
            ApprovalStatus.REJECTED,
            ApprovalStatus.EXPIRED,
            ApprovalStatus.CANCELLED,
        }:
            raise AgentApprovalConflictError
        return self._replace(
            record,
            expected_revision=expected_revision,
            expected_status=ApprovalStatus.PENDING,
            maximum_bytes=maximum_bytes,
        )

    def finish(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        if record.status not in {
            ApprovalStatus.CONSUMED,
            ApprovalStatus.EXECUTION_UNKNOWN,
        }:
            raise AgentApprovalConflictError
        return self._replace(
            record,
            expected_revision=expected_revision,
            expected_status=ApprovalStatus.EXECUTING,
            maximum_bytes=maximum_bytes,
        )

    def purge(self, *, before_epoch: int, maximum_records: int) -> int:
        if maximum_records < 1 or maximum_records > 1000:
            raise ValueError("purge bound must be between one and one thousand")
        terminal_states = (
            ApprovalStatus.REJECTED.value,
            ApprovalStatus.EXPIRED.value,
            ApprovalStatus.CANCELLED.value,
            ApprovalStatus.CONSUMED.value,
            ApprovalStatus.EXECUTION_UNKNOWN.value,
        )
        try:
            with closing(self._connect()) as connection:
                self._verify_version(connection)
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT approval_id FROM approvals WHERE terminal_epoch < ? "
                    "AND status IN (?, ?, ?, ?, ?) ORDER BY terminal_epoch LIMIT ?",
                    (before_epoch, *terminal_states, maximum_records),
                ).fetchall()
                identifiers = tuple(str(row[0]) for row in rows)
                for identifier in identifiers:
                    connection.execute(
                        "DELETE FROM approvals WHERE approval_id = ?",
                        (identifier,),
                    )
                connection.execute("COMMIT")
                return len(identifiers)
        except AgentStateUnavailableError:
            raise
        except sqlite3.Error:
            raise AgentStateUnavailableError from None
