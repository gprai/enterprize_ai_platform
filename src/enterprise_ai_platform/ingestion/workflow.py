"""Deterministic governed-ingestion coordinator for the W7-001 boundary."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Protocol

from .governance import (
    AuditRecord,
    EmbeddingEligibility,
    IngestionEvent,
    MalwareStatus,
    WorkflowState,
    canonical_sha256,
)


class ReservationStatus(StrEnum):
    NEW = "NEW"
    REPLAY = "REPLAY"
    CONFLICT = "CONFLICT"


@dataclass(frozen=True, slots=True)
class MalwareResult:
    status: MalwareStatus
    scanner_identity: str
    checked_at: datetime

    @property
    def identity(self) -> str:
        return canonical_sha256(
            {
                "checked_at": self.checked_at,
                "scanner_identity": self.scanner_identity,
                "status": self.status,
            }
        )


@dataclass(frozen=True, slots=True)
class GovernedResult:
    state: WorkflowState
    reason_code: str
    audit_records: tuple[AuditRecord, ...]
    eligibility: EmbeddingEligibility | None = None
    downstream_result: object | None = None


@dataclass(frozen=True, slots=True)
class Reservation:
    status: ReservationStatus
    prior_result: GovernedResult | None = None


class MalwareScanner(Protocol):
    async def scan(self, event: IngestionEvent) -> MalwareResult: ...


class IdempotencyStore(Protocol):
    def reserve(self, key: str, source_identity: str, content_identity: str) -> Reservation: ...
    def complete(self, key: str, result: GovernedResult) -> None: ...


class AuditSink(Protocol):
    def write(self, record: AuditRecord) -> None: ...


class PipelineRunner(Protocol):
    async def run(self, eligibility: EmbeddingEligibility) -> object: ...


_TERMINAL = {
    WorkflowState.INDEXED,
    WorkflowState.QUARANTINED,
    WorkflowState.DEAD_LETTERED,
    WorkflowState.CANCELLED,
}

_ALLOWED: dict[WorkflowState | None, frozenset[WorkflowState]] = {
    None: frozenset({WorkflowState.RECEIVED}),
    WorkflowState.RECEIVED: frozenset({WorkflowState.VALIDATED, WorkflowState.QUARANTINED}),
    WorkflowState.VALIDATED: frozenset({WorkflowState.RESERVED, WorkflowState.QUARANTINED}),
    WorkflowState.RESERVED: frozenset(
        {WorkflowState.MALWARE_PASSED, WorkflowState.QUARANTINED, WorkflowState.CANCELLED}
    ),
    WorkflowState.MALWARE_PASSED: frozenset({WorkflowState.PII_APPROVED}),
    WorkflowState.PII_APPROVED: frozenset({WorkflowState.PROCESSED}),
    WorkflowState.PROCESSED: frozenset({WorkflowState.EMBEDDING_ELIGIBLE}),
    WorkflowState.EMBEDDING_ELIGIBLE: frozenset(
        {WorkflowState.INDEXED, WorkflowState.DEAD_LETTERED}
    ),
}


class GovernedIngestionWorkflow:
    """Create eligibility once, then call the unchanged ingestion pipeline once."""

    def __init__(
        self,
        *,
        malware_scanner: MalwareScanner,
        idempotency_store: IdempotencyStore,
        audit_sink: AuditSink,
        pipeline_runner: PipelineRunner,
        clock: Callable[[], datetime],
    ) -> None:
        self._malware_scanner = malware_scanner
        self._idempotency_store = idempotency_store
        self._audit_sink = audit_sink
        self._pipeline_runner = pipeline_runner
        self._clock = clock

    async def process(self, event: IngestionEvent) -> GovernedResult:
        audits: list[AuditRecord] = []
        source_identity = canonical_sha256(event.source)
        current: WorkflowState | None = None

        reservation = self._idempotency_store.reserve(
            event.idempotency_key,
            source_identity,
            event.source.original_content_sha256,
        )
        if reservation.status is ReservationStatus.REPLAY:
            if reservation.prior_result is None:
                raise ValueError("replay is missing its prior deterministic result")
            return reservation.prior_result

        def transition(next_state: WorkflowState, reason: str) -> None:
            nonlocal current
            if current in _TERMINAL or next_state not in _ALLOWED.get(current, frozenset()):
                raise ValueError("illegal governed-ingestion transition")
            prior_hash = audits[-1].transition_sha256 if audits else None
            timestamp = self._clock()
            transition_hash = canonical_sha256(
                {
                    "correlation_id": event.processing.correlation_id,
                    "next_state": next_state,
                    "previous_state": current,
                    "prior_transition_sha256": prior_hash,
                    "reason_code": reason,
                    "source_identity_sha256": source_identity,
                    "timestamp": timestamp,
                }
            )
            record = AuditRecord(
                previous_state=current,
                next_state=next_state,
                safe_reason_code=reason,
                correlation_id=event.processing.correlation_id,
                source_identity_sha256=source_identity,
                prior_transition_sha256=prior_hash,
                transition_sha256=transition_hash,
                timestamp=timestamp,
            )
            self._audit_sink.write(record)
            audits.append(record)
            current = next_state

        transition(WorkflowState.RECEIVED, "EVENT_RECEIVED")
        observed_age = self._clock() - event.processing.observed_at
        if observed_age < timedelta(0) or observed_age > timedelta(hours=24):
            transition(WorkflowState.QUARANTINED, "STALE_OR_FUTURE_EVENT")
            result = GovernedResult(
                WorkflowState.QUARANTINED,
                "STALE_OR_FUTURE_EVENT",
                tuple(audits),
            )
            self._idempotency_store.complete(event.idempotency_key, result)
            return result
        transition(WorkflowState.VALIDATED, "METADATA_VALID")
        if reservation.status is ReservationStatus.CONFLICT:
            transition(WorkflowState.QUARANTINED, "IDEMPOTENCY_CONFLICT")
            result = GovernedResult(
                WorkflowState.QUARANTINED,
                "IDEMPOTENCY_CONFLICT",
                tuple(audits),
            )
            self._idempotency_store.complete(event.idempotency_key, result)
            return result
        transition(WorkflowState.RESERVED, "IDEMPOTENCY_RESERVED")

        try:
            malware = await self._malware_scanner.scan(event)
        except asyncio.CancelledError:
            transition(WorkflowState.CANCELLED, "CANCELLED_BEFORE_ELIGIBILITY")
            result = GovernedResult(
                WorkflowState.CANCELLED,
                "CANCELLED_BEFORE_ELIGIBILITY",
                tuple(audits),
            )
            self._idempotency_store.complete(event.idempotency_key, result)
            return result
        except Exception:
            malware = MalwareResult(MalwareStatus.ERROR, "scanner-error", self._clock())

        if malware.status is not MalwareStatus.CLEAN:
            transition(WorkflowState.QUARANTINED, f"MALWARE_{malware.status.value}")
            result = GovernedResult(
                WorkflowState.QUARANTINED,
                f"MALWARE_{malware.status.value}",
                tuple(audits),
            )
            self._idempotency_store.complete(event.idempotency_key, result)
            return result

        transition(WorkflowState.MALWARE_PASSED, "MALWARE_PASS")
        transition(WorkflowState.PII_APPROVED, f"PII_{event.pii_disposition}")
        transition(WorkflowState.PROCESSED, "PROCESSED_OBJECT_IDENTIFIED")
        eligibility = EmbeddingEligibility(
            schema_version="w7-001.embedding-eligibility.v1",
            event_id=event.processing.event_id,
            processing_id=event.processing.processing_id,
            correlation_id=event.processing.correlation_id,
            tenant_id=event.governance.tenant_id,
            classification=event.governance.classification,
            source_identity_sha256=source_identity,
            content_sha256=event.source.original_content_sha256,
            idempotency_key=event.idempotency_key,
            malware_result_identity=malware.identity,
            pii_decision_identity=event.pii_decision_identity,
            issued_at=self._clock(),
        )
        transition(WorkflowState.EMBEDDING_ELIGIBLE, "EMBEDDING_ELIGIBILITY_ISSUED")
        try:
            downstream = await self._pipeline_runner.run(eligibility)
        except Exception:
            transition(WorkflowState.DEAD_LETTERED, "DOWNSTREAM_RETRY_EXHAUSTED")
            result = GovernedResult(
                WorkflowState.DEAD_LETTERED,
                "DOWNSTREAM_RETRY_EXHAUSTED",
                tuple(audits),
                eligibility,
            )
        else:
            transition(WorkflowState.INDEXED, "INDEXING_COMPLETED")
            result = GovernedResult(
                WorkflowState.INDEXED,
                "INDEXING_COMPLETED",
                tuple(audits),
                eligibility,
                downstream,
            )
        self._idempotency_store.complete(event.idempotency_key, result)
        return result
