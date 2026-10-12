"""Deterministic local fakes for the W7-001 governed-ingestion boundary."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from enterprise_ai_platform.ingestion.governance import (
    AuditRecord,
    CatalogColumn,
    CatalogContract,
    EmbeddingEligibility,
    GovernanceMetadata,
    IngestionEvent,
    MalwareStatus,
    ProcessingIdentity,
    SourceIdentity,
    canonical_sha256,
)
from enterprise_ai_platform.ingestion.workflow import (
    GovernedResult,
    MalwareResult,
    Reservation,
    ReservationStatus,
)


@dataclass(slots=True)
class FakeMalwareScanner:
    status: MalwareStatus
    now: datetime
    fail: bool = False
    calls: int = 0

    async def scan(self, event: IngestionEvent) -> MalwareResult:
        self.calls += 1
        if self.fail:
            raise RuntimeError("synthetic scanner failure")
        return MalwareResult(self.status, "w7-local-fake-v1", self.now)


@dataclass(slots=True)
class InMemoryIdempotencyStore:
    identities: dict[str, tuple[str, str]] = field(default_factory=dict)
    results: dict[str, GovernedResult] = field(default_factory=dict)

    def reserve(self, key: str, source_identity: str, content_identity: str) -> Reservation:
        current = self.identities.get(key)
        proposed = (source_identity, content_identity)
        if current is None:
            self.identities[key] = proposed
            return Reservation(ReservationStatus.NEW)
        if current != proposed:
            return Reservation(ReservationStatus.CONFLICT)
        return Reservation(ReservationStatus.REPLAY, self.results.get(key))

    def complete(self, key: str, result: GovernedResult) -> None:
        self.results.setdefault(key, result)


@dataclass(slots=True)
class RecordingAuditSink:
    records: list[AuditRecord] = field(default_factory=list)

    def write(self, record: AuditRecord) -> None:
        self.records.append(record)


@dataclass(slots=True)
class RecordingPipelineRunner:
    result: object = "indexed"
    fail: bool = False
    calls: list[EmbeddingEligibility] = field(default_factory=list)

    async def run(self, eligibility: EmbeddingEligibility) -> object:
        self.calls.append(eligibility)
        if self.fail:
            raise RuntimeError("synthetic downstream exhaustion")
        return self.result


FIXED_NOW = datetime(2026, 10, 11, 0, 0, tzinfo=UTC)
FIXED_HASH = "a" * 64


def make_event(
    *, idempotency_key: str | None = None, content_hash: str = FIXED_HASH
) -> IngestionEvent:
    source = SourceIdentity(
        schema_version="w7-001.source.v1",
        bucket="enterprise-ai-platform-526338061652-ap-southeast-1-sandbox",
        key="raw/tenant-a/document.txt",
        s3_version_id="version-1",
        etag="etag-1",
        byte_count=12,
        media_type="text/plain",
        original_content_sha256=content_hash,
    )
    return IngestionEvent(
        schema_version="w7-001.event.v1",
        detail_type="GovernedDocumentReceived",
        source=source,
        governance=GovernanceMetadata(
            tenant_id="tenant-a",
            classification="INTERNAL",
            data_owner="owner-a",
            residency_region="ap-southeast-1",
            retention_class="raw-7d",
            retention_until=FIXED_NOW + timedelta(days=7),
            deletion_after=FIXED_NOW + timedelta(days=7),
        ),
        processing=ProcessingIdentity(
            event_id="event-1",
            processing_id="processing-1",
            correlation_id="correlation-1",
            attempt=1,
            observed_at=FIXED_NOW,
            policy_configuration_sha256="b" * 64,
        ),
        idempotency_key=idempotency_key or canonical_sha256(source),
        pii_disposition="CLEAR",
        pii_decision_identity="c" * 64,
        catalog=CatalogContract(
            database_name="enterprise_ai",
            table_name="processed_documents",
            columns=(
                CatalogColumn(name="tenant_id", type="string", nullable=False),
                CatalogColumn(name="content_sha256", type="string", nullable=False),
                CatalogColumn(name="processed_at", type="timestamp", nullable=False),
            ),
            partition_keys=("tenant_id",),
            schema_version="w7-001.catalog.v1",
            location_prefix="processed/",
        ),
    )
