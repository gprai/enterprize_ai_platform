"""Feature coverage for W7-002 replay, drift, and duplicate behavior."""

from __future__ import annotations

import pytest

from enterprise_ai_platform.processing.contracts import ProcessingState, QualityStatus
from enterprise_ai_platform.processing.pipeline import ProcessingCoordinator
from tests.fakes.w7_002_processing import (
    FakePiiVerifier,
    InMemoryCheckpointStore,
    InMemoryReplaySourceProvider,
    RecordingIndexer,
    RecordingReportSink,
    make_batch,
    make_document,
    processing_config,
)


def build_coordinator(
    values: dict[str, bytes],
) -> tuple[ProcessingCoordinator, RecordingIndexer, InMemoryCheckpointStore, RecordingReportSink]:
    indexer = RecordingIndexer()
    checkpoints = InMemoryCheckpointStore()
    reports = RecordingReportSink()
    return (
        ProcessingCoordinator(
            config=processing_config(),
            source_provider=InMemoryReplaySourceProvider(values),
            pii_verifier=FakePiiVerifier(),
            indexer=indexer,
            checkpoint_store=checkpoints,
            report_sink=reports,
        ),
        indexer,
        checkpoints,
        reports,
    )


@pytest.mark.asyncio
async def test_exact_duplicate_is_skipped_without_duplicate_embedding() -> None:
    first, content = make_document(document_id="document-1", idempotency_key="a" * 64)
    duplicate_raw = first.model_dump(mode="python")
    duplicate_raw["document_id"] = "document-2"
    duplicate = type(first).model_validate(duplicate_raw, strict=False)
    coordinator, indexer, _, _ = build_coordinator({first.source.identity: content})

    result = await coordinator.process_batch(make_batch((first, duplicate)))

    assert result.decisions[1].state is ProcessingState.SKIPPED_DUPLICATE
    assert indexer.calls == ["document-1"]


@pytest.mark.asyncio
async def test_dry_run_is_deterministic_and_writes_no_checkpoint_or_report() -> None:
    document, content = make_document()
    coordinator, indexer, checkpoints, reports = build_coordinator(
        {document.source.identity: content}
    )
    batch = make_batch((document,), dry_run=True)

    first = await coordinator.process_batch(batch)
    second = await coordinator.process_batch(batch)

    assert first == second
    assert first.decisions[0].state is ProcessingState.VALIDATED
    assert indexer.calls == []
    assert checkpoints.values == {}
    assert reports.reports == {}


@pytest.mark.asyncio
async def test_volume_drift_quarantines_prepared_document() -> None:
    document, content = make_document()
    coordinator, indexer, _, _ = build_coordinator({document.source.identity: content})

    result = await coordinator.process_batch(make_batch((document,), expected_document_count=3))

    assert result.quality_report.status is QualityStatus.FAIL
    assert result.decisions[0].state is ProcessingState.QUARANTINED
    assert indexer.calls == []


@pytest.mark.asyncio
async def test_embedding_retry_exhaustion_is_dead_lettered_and_counted() -> None:
    document, content = make_document()
    indexer = RecordingIndexer(
        failures_before_success=2,
        safe_failure_code="EMBEDDING_RETRY_EXHAUSTED",
    )
    coordinator = ProcessingCoordinator(
        config=processing_config(),
        source_provider=InMemoryReplaySourceProvider({document.source.identity: content}),
        pii_verifier=FakePiiVerifier(),
        indexer=indexer,
        checkpoint_store=InMemoryCheckpointStore(),
        report_sink=RecordingReportSink(),
    )

    result = await coordinator.process_batch(make_batch((document,)))

    assert result.decisions[0].state is ProcessingState.DEAD_LETTERED
    metric = next(
        item
        for item in result.quality_report.metrics
        if item.name.value == "w7_processing_embedding_failure_total"
    )
    assert metric.count == 1
