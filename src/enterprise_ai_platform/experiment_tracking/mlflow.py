"""Bounded process-local MLflow-compatible store with no vendor or network dependency."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import RLock

from .errors import ExperimentAdmissionError, ExperimentStateError, ExperimentValidationError
from .models import (
    ExperimentInput,
    ExperimentRun,
    RedactedLineageExport,
    RunEnvelope,
    RunStatus,
)
from .serialization import fingerprint


class InMemoryMlflowStore:
    """Expose run lifecycle semantics without files, sockets, SDKs, or environment access."""

    def __init__(self, *, maximum_records: int = 100) -> None:
        if maximum_records != 100:
            raise ExperimentValidationError("the approved retained-run bound is one hundred")
        self._maximum_records = maximum_records
        self._records: dict[str, ExperimentRun] = {}
        self._disabled = False
        self._latest_export_identity: str | None = None
        self._lock = RLock()

    @property
    def disabled(self) -> bool:
        with self._lock:
            return self._disabled

    def create(self, envelope: RunEnvelope, experiment_input: ExperimentInput) -> ExperimentRun:
        with self._lock:
            if self._disabled:
                raise ExperimentStateError("experiment tracking is disabled")
            if envelope.run_id in self._records:
                raise ExperimentAdmissionError("run ID already exists")
            if len(self._records) >= self._maximum_records:
                raise ExperimentAdmissionError("retained-run limit exceeded")
            record = ExperimentRun(
                envelope=envelope,
                input_identity_sha256=fingerprint(experiment_input),
                experiment_input=experiment_input,
                status=RunStatus.RUNNING,
            )
            self._records[envelope.run_id] = record
            return record

    def terminate(
        self,
        run_id: str,
        status: RunStatus,
        *,
        completed_at: datetime,
        safe_reason_code: str | None = None,
    ) -> ExperimentRun:
        if status is RunStatus.RUNNING:
            raise ExperimentStateError("termination requires a terminal status")
        if completed_at.tzinfo is None or completed_at.utcoffset() != UTC.utcoffset(completed_at):
            raise ExperimentValidationError("completion time must use UTC")
        with self._lock:
            current = self.get(run_id)
            if current.status is not RunStatus.RUNNING:
                raise ExperimentStateError("terminal runs are immutable")
            updated = current.model_copy(
                update={
                    "status": status,
                    "completed_at": completed_at,
                    "safe_reason_code": safe_reason_code,
                }
            )
            updated = ExperimentRun.model_validate(updated.model_dump(mode="python"), strict=True)
            self._records[run_id] = updated
            return updated

    def get(self, run_id: str) -> ExperimentRun:
        with self._lock:
            try:
                return self._records[run_id]
            except KeyError:
                raise ExperimentStateError("run does not exist") from None

    def list(self) -> tuple[ExperimentRun, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))

    def disable(self) -> None:
        with self._lock:
            if any(record.status is RunStatus.RUNNING for record in self._records.values()):
                raise ExperimentStateError("active runs must terminate before disablement")
            self._disabled = True

    def export(self, *, policy_sha256: str, exported_at: datetime) -> RedactedLineageExport:
        with self._lock:
            if not self._disabled:
                raise ExperimentStateError("tracking must be disabled before export")
            exported = RedactedLineageExport(
                policy_sha256=policy_sha256,
                exported_at=exported_at,
                records=self.list(),
            )
            self._latest_export_identity = fingerprint(exported)
            return exported

    def purge(self, run_ids: tuple[str, ...], *, export_identity_sha256: str) -> None:
        with self._lock:
            if not self._disabled:
                raise ExperimentStateError("tracking must be disabled before purge")
            if self._latest_export_identity != export_identity_sha256:
                raise ExperimentStateError("purge is not bound to the latest redacted export")
            if run_ids != tuple(sorted(set(run_ids))):
                raise ExperimentValidationError("purge run IDs must be sorted and unique")
            if run_ids != tuple(sorted(self._records)):
                raise ExperimentStateError("purge must name the exact exported run inventory")
            for run_id in run_ids:
                del self._records[run_id]
