"""Deterministic local fakes for W7-002 processing."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Literal

from enterprise_ai_platform.ingestion.governance import EmbeddingEligibility, canonical_sha256
from enterprise_ai_platform.processing.contracts import (
    DocumentRequest,
    PartitionMetadata,
    PreparedDocument,
    ProcessingBatchRequest,
    ProcessingCheckpoint,
    ProcessingConfig,
    ReplaySourceIdentity,
    load_processing_config,
)

FIXED_NOW = datetime(2026, 10, 12, 0, 0, tzinfo=UTC)


@dataclass(slots=True)
class InMemoryReplaySourceProvider:
    values: dict[str, bytes]
    calls: list[str] = field(default_factory=list)

    async def read(self, source: ReplaySourceIdentity) -> bytes:
        self.calls.append(source.identity)
        return self.values[source.identity]


@dataclass(slots=True)
class FakePiiVerifier:
    rejected: frozenset[str] = frozenset()
    fail: frozenset[str] = frozenset()
    calls: list[str] = field(default_factory=list)

    async def verify(self, document: DocumentRequest, normalized_text: str) -> bool:
        del normalized_text
        self.calls.append(document.document_id)
        if document.document_id in self.fail:
            raise RuntimeError("synthetic PII verifier failure")
        return document.document_id not in self.rejected


@dataclass(slots=True)
class RecordingIndexer:
    failures_before_success: int = 0
    safe_failure_code: str | None = None
    calls: list[str] = field(default_factory=list)

    async def index(self, document: PreparedDocument) -> object:
        self.calls.append(document.document_id)
        if len(self.calls) <= self.failures_before_success:
            if self.safe_failure_code is not None:
                from enterprise_ai_platform.processing.pipeline import ProcessingError

                raise ProcessingError(self.safe_failure_code, retryable=True)
            raise RuntimeError("synthetic indexing failure")
        return "indexed"


@dataclass(slots=True)
class InMemoryCheckpointStore:
    values: dict[tuple[str, str], ProcessingCheckpoint] = field(default_factory=dict)
    writes: int = 0

    def get(self, batch_id: str, document_id: str) -> ProcessingCheckpoint | None:
        return self.values.get((batch_id, document_id))

    def compare_and_set(
        self,
        expected: ProcessingCheckpoint | None,
        checkpoint: ProcessingCheckpoint,
    ) -> None:
        key = (checkpoint.batch_id, checkpoint.document_id)
        if self.values.get(key) != expected:
            raise RuntimeError("synthetic checkpoint conflict")
        self.values[key] = checkpoint
        self.writes += 1


@dataclass(slots=True)
class RecordingReportSink:
    reports: dict[str, object] = field(default_factory=dict)

    def write(self, report_identity: str, report: object) -> None:
        self.reports.setdefault(report_identity, report)


@dataclass(frozen=True, slots=True)
class StaticRequestResolver:
    batch: ProcessingBatchRequest

    def resolve(self, eligibility: EmbeddingEligibility) -> ProcessingBatchRequest:
        if not any(document.eligibility == eligibility for document in self.batch.documents):
            raise ValueError("eligibility not present")
        return self.batch


def processing_config() -> ProcessingConfig:
    from pathlib import Path

    return load_processing_config(Path("configs/processing/document-quality-replay.yaml"))


def make_document(
    *,
    document_id: str = "document-1",
    tenant_id: str = "tenant-a",
    content: bytes = b"approved synthetic content\n",
    idempotency_key: str | None = None,
    classification: Literal["PUBLIC", "INTERNAL"] = "INTERNAL",
) -> tuple[DocumentRequest, bytes]:
    content_sha256 = hashlib.sha256(content).hexdigest()
    upstream_source_identity = canonical_sha256(
        {"document_id": document_id, "tenant_id": tenant_id}
    )
    source = ReplaySourceIdentity(
        schema_version="w7-002.replay-source.v1",
        bucket="enterprise-ai-platform-526338061652-ap-southeast-1-sandbox",
        key=f"raw/{tenant_id}/{document_id}.txt",
        version_id=f"version-{document_id}",
        etag=f"etag-{document_id}",
        byte_count=len(content),
        media_type="text/plain",
        content_sha256=content_sha256,
        upstream_source_identity_sha256=upstream_source_identity,
        selected_at=FIXED_NOW,
    )
    eligibility = EmbeddingEligibility(
        schema_version="w7-001.embedding-eligibility.v1",
        event_id=f"event-{document_id}",
        processing_id=f"processing-{document_id}",
        correlation_id=f"correlation-{document_id}",
        tenant_id=tenant_id,
        classification=classification,
        source_identity_sha256=upstream_source_identity,
        content_sha256=content_sha256,
        idempotency_key=idempotency_key or canonical_sha256(source),
        malware_result_identity="b" * 64,
        pii_decision_identity="c" * 64,
        issued_at=FIXED_NOW,
    )
    return (
        DocumentRequest(
            schema_version="w7-002.processing-request.v1",
            document_id=document_id,
            eligibility=eligibility,
            source=source,
            partition=PartitionMetadata(
                tenant_id=tenant_id,
                classification=classification,
                processing_date="2026-10-12",
            ),
        ),
        content,
    )


def make_batch(
    documents: tuple[DocumentRequest, ...],
    *,
    expected_document_count: int | None = None,
    dry_run: bool = False,
) -> ProcessingBatchRequest:
    config = processing_config()
    return ProcessingBatchRequest(
        schema_version="w7-002.batch.v1",
        batch_id="batch-1",
        tenant_id="tenant-a",
        expected_document_count=expected_document_count or len(documents),
        documents=documents,
        requested_at=FIXED_NOW,
        dry_run=dry_run,
        policy_configuration_sha256=config.identity,
    )
