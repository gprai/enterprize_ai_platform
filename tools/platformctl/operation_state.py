"""External atomic operation lock and one-time approval consumption ledger."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from string import ascii_letters, ascii_uppercase, digits
from typing import cast

from .contracts import (
    Action,
    ApprovalError,
    ApprovalStateUnavailable,
    ApprovalUsageRegistry,
    ContractError,
    VerifiedExecutionContext,
    parse_utc_timestamp,
    validate_sha256,
)
from .lifecycle_io import (
    canonical_json_bytes,
    ensure_external_path,
    load_json_strict,
    private_directory_chain,
    reserve_operation_directory,
    sha256_bytes,
    verify_private_directory,
    write_canonical_json_atomic,
)
from .lifecycle_models import (
    LIFECYCLE_SCHEMA_VERSION,
    OPERATIONAL_SCHEMA_VERSION,
    OperationLock,
    OperationPhase,
    OperationResultV2,
    Outcome,
    PurgeItem,
)


class OperationStateError(ContractError):
    """Raised for conflict, stale state, or unclassified ledger failure."""


class OperationLedger(ApprovalUsageRegistry):
    """Fail-closed external ledger with O_EXCL mutual exclusion."""

    def __init__(self, root: Path, repository_root: Path) -> None:
        self._root = ensure_external_path(root, root, repository_root)
        self._repository_root = repository_root.resolve(strict=True)
        try:
            if not self._root.exists():
                reserve_operation_directory(self._root, self._root, self._repository_root)
            verify_private_directory(self._root)
        except OSError as exc:
            raise OperationStateError("operation ledger root is unavailable") from exc

    @property
    def lock_path(self) -> Path:
        """Return the single lifecycle-operation lock path."""
        return self._root / "operation.lock.json"

    def _exclusive_write(self, path: Path, value: object) -> None:
        target = ensure_external_path(path, self._root, self._repository_root)
        private_directory_chain(target.parent, self._root, self._repository_root)
        try:
            write_canonical_json_atomic(
                target, value, allowed_root=self._root, repository_root=self._repository_root
            )
        except FileExistsError as exc:
            raise OperationStateError("operation or approval is already recorded") from exc
        except OSError as exc:
            raise OperationStateError("operation ledger write failed") from exc
        except ContractError as exc:
            raise OperationStateError(
                "operation or approval is already recorded or unavailable"
            ) from exc

    def acquire(self, lock: OperationLock, now: datetime) -> None:
        """Acquire one exact operation without replacing a stale lock."""
        if lock.schema_version != LIFECYCLE_SCHEMA_VERSION:
            raise OperationStateError("operation lock schema is not approved")
        _operation_name(lock.operation_id)
        try:
            Action(lock.action)
        except ValueError as exc:
            raise OperationStateError("operation lock action is not approved") from exc
        validate_sha256(lock.artifact_sha256)
        created_at = parse_utc_timestamp(lock.created_at, "operation created_at")
        expires_at = parse_utc_timestamp(lock.expires_at, "operation expires_at")
        if created_at > now or expires_at <= now:
            raise OperationStateError("operation lock time boundary is invalid")
        if (expires_at - created_at).total_seconds() > 3600:
            raise OperationStateError("operation lock lifetime exceeds 60 minutes")
        self._exclusive_write(self.lock_path, lock)

    def release(self, operation_id: str) -> None:
        """Release only a matching active operation; never repair stale state."""
        _operation_name(operation_id)
        target = ensure_external_path(self.lock_path, self._root, self._repository_root)
        try:
            original = target.stat()
            value = load_json_strict(target)
        except (OSError, json.JSONDecodeError, TypeError) as exc:
            raise OperationStateError("operation lock is unavailable or malformed") from exc
        if not isinstance(value, dict) or value.get("operation_id") != operation_id:
            raise OperationStateError("operation lock owner does not match")
        history = self.journal(operation_id)
        if history and history[-1]["state"] != OperationPhase.POST_EXECUTION_VERIFIED.value:
            raise OperationStateError("POST_VERIFICATION_REQUIRED_BEFORE_LOCK_RELEASE")
        try:
            current = target.stat()
            if (original.st_dev, original.st_ino, original.st_size, original.st_mtime_ns) != (
                current.st_dev,
                current.st_ino,
                current.st_size,
                current.st_mtime_ns,
            ):
                raise OperationStateError("OPERATION_LOCK_IDENTITY_CHANGED")
            ensure_external_path(target, self._root, self._repository_root)
            target.unlink()
        except OSError as exc:
            raise OperationStateError("operation lock release failed") from exc

    def is_used(self, approval_id: str) -> bool:
        """Return whether the approval has an exact consumed marker."""
        _operation_name(approval_id)
        marker = ensure_external_path(
            self._root / "approvals" / f"{approval_id}.json",
            self._root,
            self._repository_root,
        )
        try:
            marker.stat()
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise ApprovalStateUnavailable("approval reuse state is unavailable") from exc
        if not marker.is_file() or marker.is_symlink():
            raise ApprovalStateUnavailable("approval reuse state is not an ordinary file")
        return True

    def consume(self, approval_id: str, artifact_sha256: str, consumed_at: str) -> None:
        """Atomically consume one approval before any approved mutation starts."""
        _operation_name(approval_id)
        validate_sha256(artifact_sha256)
        parse_utc_timestamp(consumed_at, "approval consumed_at")
        try:
            # Reserve artifact identity first. A torn two-record write remains
            # consumed/unusable and needs reconciliation; never compensate by deletion.
            self._exclusive_write(
                self._root / "consumed-artifacts" / f"{artifact_sha256}.json",
                {
                    "schema_version": OPERATIONAL_SCHEMA_VERSION,
                    "artifact_sha256": artifact_sha256,
                    "approval_id": approval_id,
                    "consumed_at": consumed_at,
                },
            )
            self._exclusive_write(
                self._root / "approvals" / f"{approval_id}.json",
                {
                    "schema_version": LIFECYCLE_SCHEMA_VERSION,
                    "approval_id": approval_id,
                    "artifact_sha256": artifact_sha256,
                    "consumed_at": consumed_at,
                },
            )
        except OperationStateError as exc:
            raise ApprovalError("approval has already been used or cannot be recorded") from exc

    def journal(self, operation_id: str) -> tuple[dict[str, object], ...]:
        """Verify the whole append-only chain; incomplete consumption blocks reuse."""
        _operation_name(operation_id)
        directory = ensure_external_path(
            self._root / "operations" / operation_id, self._root, self._repository_root
        )
        if not directory.exists():
            return ()
        records: list[dict[str, object]] = []
        previous: str | None = None
        phase: OperationPhase | None = None
        for sequence, path in enumerate(sorted(directory.iterdir()), start=1):
            if path.name != f"{sequence:06d}.json":
                raise OperationStateError("JOURNAL_SEQUENCE_GAP")
            value = load_json_strict(path)
            if not isinstance(value, dict) or set(value) != {
                "schema_version",
                "operation_id",
                "sequence",
                "previous_sha256",
                "state",
                "recorded_at",
                "artifact_sha256",
                "approval_id",
                "reason_code",
            }:
                raise OperationStateError("JOURNAL_RECORD_MALFORMED")
            record = cast(dict[str, object], value)
            if (
                record["schema_version"] != OPERATIONAL_SCHEMA_VERSION
                or record["operation_id"] != operation_id
                or type(record["sequence"]) is not int
                or record["sequence"] != sequence
                or record["previous_sha256"] != previous
            ):
                raise OperationStateError("JOURNAL_IDENTITY_MISMATCH")
            try:
                next_phase = OperationPhase(cast(str, record["state"]))
            except ValueError as exc:
                raise OperationStateError("JOURNAL_STATE_INVALID") from exc
            if next_phase not in _TRANSITIONS[phase]:
                raise OperationStateError("JOURNAL_TRANSITION_INVALID")
            previous_artifacts = {
                entry["artifact_sha256"]
                for entry in records
                if entry["artifact_sha256"] is not None
            }
            if records and (
                (bool(previous_artifacts) and record["artifact_sha256"] not in previous_artifacts)
                or parse_utc_timestamp(cast(str, record["recorded_at"]), "journal time")
                < parse_utc_timestamp(cast(str, records[-1]["recorded_at"]), "journal time")
            ):
                raise OperationStateError("JOURNAL_ARTIFACT_OR_TIME_DRIFT")
            previous = sha256_bytes(path.read_bytes())
            records.append(record)
            phase = next_phase
        return tuple(records)

    def transition(
        self,
        operation_id: str,
        state: OperationPhase,
        *,
        artifact_sha256: str | None,
        recorded_at: str,
        approval_id: str | None = None,
        reason_code: str = "NONE",
    ) -> None:
        """Append a single exclusive durable transition; never overwrite history."""
        _operation_name(operation_id)
        if artifact_sha256 is None:
            if state not in {OperationPhase.PREPARED, OperationPhase.REVIEW_FAILED}:
                raise OperationStateError("JOURNAL_ARTIFACT_REQUIRED")
        else:
            validate_sha256(artifact_sha256)
        parse_utc_timestamp(recorded_at, "journal time")
        if not reason_code or any(c not in ascii_uppercase + digits + "_" for c in reason_code):
            raise OperationStateError("JOURNAL_REASON_INVALID")
        history = self.journal(operation_id)
        current = OperationPhase(cast(str, history[-1]["state"])) if history else None
        if state not in _TRANSITIONS[current]:
            raise OperationStateError("JOURNAL_TRANSITION_INVALID")
        known_artifacts = {
            entry["artifact_sha256"] for entry in history if entry["artifact_sha256"] is not None
        }
        if known_artifacts and artifact_sha256 not in known_artifacts:
            raise OperationStateError("JOURNAL_ARTIFACT_CHANGED")
        if approval_id is not None:
            _operation_name(approval_id)
        self._exclusive_write(
            self._root / "operations" / operation_id / f"{len(history) + 1:06d}.json",
            {
                "schema_version": OPERATIONAL_SCHEMA_VERSION,
                "operation_id": operation_id,
                "sequence": len(history) + 1,
                "previous_sha256": sha256_bytes(canonical_json_bytes(history[-1]))
                if history
                else None,
                "state": state.value,
                "recorded_at": recorded_at,
                "artifact_sha256": artifact_sha256,
                "approval_id": approval_id,
                "reason_code": reason_code,
            },
        )

    def execution_started(self, operation_id: str, approval_id: str) -> bool:
        """A consumed marker without the matching started journal requires reconciliation."""
        history = self.journal(operation_id)
        used = self.is_used(approval_id)
        started = bool(history) and history[-1]["state"] == OperationPhase.EXECUTION_STARTED.value
        if used and (not started or history[-1]["approval_id"] != approval_id):
            raise OperationStateError("CONSUMED_APPROVAL_RECONCILIATION_REQUIRED")
        if started and not used:
            raise OperationStateError("STARTED_WITHOUT_CONSUMPTION")
        return used and started

    def begin_execution(self, context: VerifiedExecutionContext, now: datetime) -> None:
        """Acquire the shared lock, revalidate, then consume before dispatch."""
        package = context.package
        history = self.journal(package.operation_id)
        if not history or history[-1]["state"] != OperationPhase.ELIGIBLE_FOR_REVIEW.value:
            raise OperationStateError("REVIEW_JOURNAL_REQUIRED")
        timestamp = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        self.acquire(
            OperationLock(
                LIFECYCLE_SCHEMA_VERSION,
                package.operation_id,
                package.action.value,
                package.environment,
                package.target,
                package.artifact.sha256,
                timestamp,
                context.approval.expires_at,
            ),
            now,
        )
        # Reject before consuming whenever possible; retain lock on any ambiguous failure.
        context.revalidate(package.action, package.artifact.sha256, consumed=False)
        self.transition(
            package.operation_id,
            OperationPhase.APPROVED,
            artifact_sha256=package.artifact.sha256,
            recorded_at=timestamp,
            approval_id=context.approval.approval_id,
        )
        self.consume(context.approval.approval_id, package.artifact.sha256, timestamp)
        self.transition(
            package.operation_id,
            OperationPhase.EXECUTION_STARTED,
            artifact_sha256=package.artifact.sha256,
            recorded_at=timestamp,
            approval_id=context.approval.approval_id,
        )

    def finish_execution(
        self,
        context: VerifiedExecutionContext,
        state: OperationPhase,
        reason_code: str,
    ) -> OperationResultV2:
        """Persist completion separately from verification; preserve consumed authority."""
        if state not in {
            OperationPhase.EXECUTION_COMPLETED,
            OperationPhase.EXECUTION_FAILED,
            OperationPhase.EXECUTION_OUTCOME_UNCERTAIN,
        }:
            raise OperationStateError("EXECUTION_TERMINAL_STATE_INVALID")
        package = context.package
        if not self.execution_started(package.operation_id, context.approval.approval_id):
            raise OperationStateError("EXECUTION_START_REQUIRED")
        successful = state is OperationPhase.EXECUTION_COMPLETED
        classification = Outcome.PASS if successful else Outcome.FAIL
        if state is OperationPhase.EXECUTION_OUTCOME_UNCERTAIN:
            classification = Outcome.INDETERMINATE
        result = OperationResultV2(
            OPERATIONAL_SCHEMA_VERSION,
            package.operation_id,
            "EXECUTION",
            state,
            classification,
            0 if successful else 1,
            reason_code,
            context.dispatch_started,
            Outcome.NOT_RUN,
            Outcome.NOT_RUN,
            (package.artifact,),
        )
        self.transition(
            package.operation_id,
            state,
            artifact_sha256=package.artifact.sha256,
            recorded_at=context.current_timestamp(),
            approval_id=context.approval.approval_id,
            reason_code=reason_code,
        )
        # A failed result write leaves a terminal journal plus the consumed marker.
        # The caller must return uncertainty and must not retry or release the lock.
        self._exclusive_write(self._root / "results" / f"{package.operation_id}.json", result)
        return result

    def start_purge_batch(
        self, context: VerifiedExecutionContext, sequence: int, item: PurgeItem
    ) -> None:
        """Exclusive per-item consumption; a started batch can never be retried."""
        if not self.execution_started(context.package.operation_id, context.approval.approval_id):
            raise OperationStateError("PURGE_EXECUTION_START_REQUIRED")
        if type(sequence) is not int or not 1 <= sequence <= 10000:
            raise OperationStateError("PURGE_SEQUENCE_INVALID")
        root = self._root / "batches" / context.package.operation_id
        previous = root / f"{sequence - 1:06d}.complete.json"
        if sequence > 1:
            self._purge_chain(context, sequence - 1, completed=True)
        self._exclusive_write(
            root / f"{sequence:06d}.started.json",
            {
                "schema_version": OPERATIONAL_SCHEMA_VERSION,
                "operation_id": context.package.operation_id,
                "sequence": sequence,
                "artifact_sha256": context.package.artifact.sha256,
                "item_sha256": sha256_bytes(canonical_json_bytes(item)),
                "previous_sha256": sha256_bytes(previous.read_bytes()) if sequence > 1 else None,
            },
        )

    def require_purge_batch(
        self, context: VerifiedExecutionContext, sequence: int, item: PurgeItem
    ) -> None:
        root = self._root / "batches" / context.package.operation_id
        started = self._purge_chain(context, sequence, completed=False)
        if (
            started["item_sha256"] != sha256_bytes(canonical_json_bytes(item))
            or (root / f"{sequence:06d}.dispatched.json").exists()
        ):
            raise OperationStateError("PURGE_BATCH_NOT_AUTHORIZED_OR_ALREADY_DISPATCHED")
        self._exclusive_write(root / f"{sequence:06d}.dispatched.json", started)

    def complete_purge_batch(
        self, context: VerifiedExecutionContext, sequence: int, item: PurgeItem
    ) -> None:
        root = self._root / "batches" / context.package.operation_id
        started = self._purge_chain(context, sequence, completed=False)
        dispatched = self._read_purge_record(root / f"{sequence:06d}.dispatched.json")
        if dispatched != started or (
            dispatched["item_sha256"] != sha256_bytes(canonical_json_bytes(item))
        ):
            raise OperationStateError("PURGE_BATCH_DISPATCH_UNPROVEN")
        self._exclusive_write(root / f"{sequence:06d}.complete.json", dispatched)

    def _read_purge_record(self, path: Path) -> dict[str, object]:
        target = ensure_external_path(path, self._root, self._repository_root)
        value = load_json_strict(target)
        if not isinstance(value, dict) or set(value) != {
            "schema_version",
            "operation_id",
            "sequence",
            "artifact_sha256",
            "item_sha256",
            "previous_sha256",
        }:
            raise OperationStateError("PURGE_BATCH_RECORD_MALFORMED")
        return cast(dict[str, object], value)

    def _purge_chain(
        self,
        context: VerifiedExecutionContext,
        sequence: int,
        *,
        completed: bool,
    ) -> dict[str, object]:
        """Reconcile every predecessor; file existence never proves completion."""
        if type(sequence) is not int or not 1 <= sequence <= 10000:
            raise OperationStateError("PURGE_SEQUENCE_INVALID")
        if not self.execution_started(context.package.operation_id, context.approval.approval_id):
            raise OperationStateError("PURGE_EXECUTION_START_REQUIRED")
        root = self._root / "batches" / context.package.operation_id
        previous_hash: str | None = None
        current: dict[str, object] = {}
        seen: set[str] = set()
        for index in range(1, sequence + 1):
            current = self._read_purge_record(root / f"{index:06d}.started.json")
            item_hash = current["item_sha256"]
            if (
                current["schema_version"] != OPERATIONAL_SCHEMA_VERSION
                or current["operation_id"] != context.package.operation_id
                or type(current["sequence"]) is not int
                or current["sequence"] != index
                or current["artifact_sha256"] != context.package.artifact.sha256
                or current["previous_sha256"] != previous_hash
                or not isinstance(item_hash, str)
                or item_hash in seen
            ):
                raise OperationStateError("PURGE_BATCH_CHAIN_INVALID")
            validate_sha256(item_hash)
            seen.add(item_hash)
            if completed or index < sequence:
                finished_path = root / f"{index:06d}.complete.json"
                if (
                    self._read_purge_record(root / f"{index:06d}.dispatched.json") != current
                    or self._read_purge_record(finished_path) != current
                ):
                    raise OperationStateError("PURGE_PREVIOUS_BATCH_UNRECONCILED")
                previous_hash = sha256_bytes(finished_path.read_bytes())
        return current

    def record_post_verification(
        self, operation_id: str, result: OperationResultV2, now: datetime
    ) -> None:
        """Release the owned operation lock only after durable independent verification."""
        history = self.journal(operation_id)
        if (
            result.operation_id != operation_id
            or result.state is not OperationPhase.POST_EXECUTION_VERIFIED
            or result.classification is not Outcome.PASS
            or result.verification is not Outcome.PASS
            or result.exit_code != 0
            or not history
            or history[-1]["state"] != OperationPhase.EXECUTION_COMPLETED.value
            or not result.references
            or result.references[0].sha256 != history[-1]["artifact_sha256"]
        ):
            raise OperationStateError("POST_VERIFICATION_RESULT_INVALID")
        self.transition(
            operation_id,
            OperationPhase.POST_EXECUTION_VERIFIED,
            artifact_sha256=result.references[0].sha256,
            recorded_at=now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            approval_id=cast(str, history[-1]["approval_id"]),
            reason_code="POST_EXECUTION_VERIFIED",
        )
        self._exclusive_write(self._root / "results" / f"{operation_id}.verified.json", result)
        self.release(operation_id)


def _operation_name(value: str) -> None:
    if (
        not value
        or len(value) > 128
        or any(character not in ascii_letters + digits + "-_" for character in value)
    ):
        raise OperationStateError("OPERATION_ID_INVALID")


_TRANSITIONS: dict[OperationPhase | None, frozenset[OperationPhase]] = {
    None: frozenset({OperationPhase.PREPARED}),
    OperationPhase.PREPARED: frozenset(
        {OperationPhase.REVIEW_FAILED, OperationPhase.ELIGIBLE_FOR_REVIEW}
    ),
    OperationPhase.REVIEW_FAILED: frozenset(),
    OperationPhase.ELIGIBLE_FOR_REVIEW: frozenset({OperationPhase.APPROVED}),
    OperationPhase.APPROVED: frozenset({OperationPhase.EXECUTION_STARTED}),
    OperationPhase.EXECUTION_STARTED: frozenset(
        {
            OperationPhase.EXECUTION_FAILED,
            OperationPhase.EXECUTION_OUTCOME_UNCERTAIN,
            OperationPhase.EXECUTION_COMPLETED,
        }
    ),
    OperationPhase.EXECUTION_FAILED: frozenset(),
    OperationPhase.EXECUTION_OUTCOME_UNCERTAIN: frozenset(),
    OperationPhase.EXECUTION_COMPLETED: frozenset({OperationPhase.POST_EXECUTION_VERIFIED}),
    OperationPhase.POST_EXECUTION_VERIFIED: frozenset(),
}
