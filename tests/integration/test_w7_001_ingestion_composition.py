"""Composition coverage for eligibility-before-pipeline and idempotent replay."""

from __future__ import annotations

import pytest

from enterprise_ai_platform.ingestion.governance import MalwareStatus, WorkflowState
from enterprise_ai_platform.ingestion.workflow import GovernedIngestionWorkflow
from tests.fakes.w7_001_data_foundation import (
    FIXED_NOW,
    FakeMalwareScanner,
    InMemoryIdempotencyStore,
    RecordingAuditSink,
    RecordingPipelineRunner,
    make_event,
)


@pytest.mark.asyncio
async def test_valid_event_creates_eligibility_before_single_pipeline_call() -> None:
    scanner = FakeMalwareScanner(MalwareStatus.CLEAN, FIXED_NOW)
    store = InMemoryIdempotencyStore()
    sink = RecordingAuditSink()
    runner = RecordingPipelineRunner()
    workflow = GovernedIngestionWorkflow(
        malware_scanner=scanner,
        idempotency_store=store,
        audit_sink=sink,
        pipeline_runner=runner,
        clock=lambda: FIXED_NOW,
    )
    result = await workflow.process(make_event())
    assert result.state is WorkflowState.INDEXED
    assert len(runner.calls) == 1
    assert runner.calls[0] == result.eligibility
    assert sink.records[-2].next_state is WorkflowState.EMBEDDING_ELIGIBLE


@pytest.mark.asyncio
async def test_exact_replay_returns_prior_result_without_new_calls_or_transitions() -> None:
    scanner = FakeMalwareScanner(MalwareStatus.CLEAN, FIXED_NOW)
    sink = RecordingAuditSink()
    runner = RecordingPipelineRunner()
    workflow = GovernedIngestionWorkflow(
        malware_scanner=scanner,
        idempotency_store=InMemoryIdempotencyStore(),
        audit_sink=sink,
        pipeline_runner=runner,
        clock=lambda: FIXED_NOW,
    )
    event = make_event()
    first = await workflow.process(event)
    audit_count = len(sink.records)
    second = await workflow.process(event)
    assert second is first
    assert len(sink.records) == audit_count
    assert len(runner.calls) == 1
    assert scanner.calls == 1
