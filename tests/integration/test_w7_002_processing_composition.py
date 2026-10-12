"""Composition coverage for checkpointed processing and W7-001 handoff."""

from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.processing.contracts import ProcessingState
from enterprise_ai_platform.processing.pipeline import (
    ProcessingCoordinator,
    ProcessingPipelineRunner,
)
from tests.fakes.w7_002_processing import (
    FakePiiVerifier,
    InMemoryCheckpointStore,
    InMemoryReplaySourceProvider,
    RecordingIndexer,
    RecordingReportSink,
    StaticRequestResolver,
    make_batch,
    make_document,
    processing_config,
)


def coordinator_for(
    values: dict[str, bytes],
    *,
    pii: FakePiiVerifier | None = None,
    indexer: RecordingIndexer | None = None,
    checkpoints: InMemoryCheckpointStore | None = None,
    reports: RecordingReportSink | None = None,
) -> tuple[ProcessingCoordinator, RecordingIndexer, InMemoryCheckpointStore]:
    actual_indexer = indexer or RecordingIndexer()
    actual_checkpoints = checkpoints or InMemoryCheckpointStore()
    return (
        ProcessingCoordinator(
            config=processing_config(),
            source_provider=InMemoryReplaySourceProvider(values),
            pii_verifier=pii or FakePiiVerifier(),
            indexer=actual_indexer,
            checkpoint_store=actual_checkpoints,
            report_sink=reports or RecordingReportSink(),
        ),
        actual_indexer,
        actual_checkpoints,
    )


@pytest.mark.asyncio
async def test_pipeline_runner_preserves_w7_001_signature_and_checkpoints_once() -> None:
    document, content = make_document()
    batch = make_batch((document,))
    coordinator, indexer, checkpoints = coordinator_for({document.source.identity: content})
    runner = ProcessingPipelineRunner(
        resolver=StaticRequestResolver(batch),
        coordinator=coordinator,
    )

    first = await runner.run(document.eligibility)
    second = await runner.run(document.eligibility)

    assert first.decisions[0].state is ProcessingState.CURATED
    assert second.decisions[0].safe_reason_code == "CHECKPOINT_REPLAY_SKIPPED"
    assert indexer.calls == [document.document_id]
    assert checkpoints.writes == 1


@pytest.mark.asyncio
async def test_partial_pii_failure_quarantines_one_document_and_curates_the_other() -> None:
    first, first_content = make_document(document_id="document-1")
    second, second_content = make_document(document_id="document-2")
    values = {first.source.identity: first_content, second.source.identity: second_content}
    coordinator, indexer, _ = coordinator_for(
        values,
        pii=FakePiiVerifier(fail=frozenset({"document-2"})),
    )

    result = await coordinator.process_batch(make_batch((first, second)))

    assert [decision.state for decision in result.decisions] == [
        ProcessingState.CURATED,
        ProcessingState.QUARANTINED,
    ]
    assert indexer.calls == ["document-1"]


@pytest.mark.asyncio
async def test_transient_indexing_failure_retries_within_the_approved_bound() -> None:
    document, content = make_document()
    retrying_indexer = RecordingIndexer(failures_before_success=1)
    coordinator, indexer, _ = coordinator_for(
        {document.source.identity: content},
        indexer=retrying_indexer,
    )

    result = await coordinator.process_batch(make_batch((document,)))

    assert result.decisions[0].state is ProcessingState.CURATED
    assert indexer.calls == [document.document_id, document.document_id]


@pytest.mark.asyncio
async def test_cancellation_writes_no_checkpoint_and_calls_no_indexer() -> None:
    class CancellingProvider:
        async def read(self, source: object) -> bytes:
            del source
            raise asyncio.CancelledError

    document, _ = make_document()
    indexer = RecordingIndexer()
    checkpoints = InMemoryCheckpointStore()
    coordinator = ProcessingCoordinator(
        config=processing_config(),
        source_provider=CancellingProvider(),
        pii_verifier=FakePiiVerifier(),
        indexer=indexer,
        checkpoint_store=checkpoints,
        report_sink=RecordingReportSink(),
    )

    with pytest.raises(asyncio.CancelledError):
        await coordinator.process_batch(make_batch((document,)))

    assert indexer.calls == []
    assert checkpoints.values == {}
