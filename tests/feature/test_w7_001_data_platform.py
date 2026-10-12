"""Feature coverage for governed quarantine and terminal handling."""

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
@pytest.mark.parametrize("status", [MalwareStatus.DETECTED, MalwareStatus.UNKNOWN])
async def test_unsafe_malware_status_never_reaches_pipeline(status: MalwareStatus) -> None:
    runner = RecordingPipelineRunner()
    workflow = GovernedIngestionWorkflow(
        malware_scanner=FakeMalwareScanner(status, FIXED_NOW),
        idempotency_store=InMemoryIdempotencyStore(),
        audit_sink=RecordingAuditSink(),
        pipeline_runner=runner,
        clock=lambda: FIXED_NOW,
    )
    result = await workflow.process(make_event())
    assert result.state is WorkflowState.QUARANTINED
    assert runner.calls == []


@pytest.mark.asyncio
async def test_downstream_exhaustion_is_dead_lettered() -> None:
    runner = RecordingPipelineRunner(fail=True)
    workflow = GovernedIngestionWorkflow(
        malware_scanner=FakeMalwareScanner(MalwareStatus.CLEAN, FIXED_NOW),
        idempotency_store=InMemoryIdempotencyStore(),
        audit_sink=RecordingAuditSink(),
        pipeline_runner=runner,
        clock=lambda: FIXED_NOW,
    )
    assert (await workflow.process(make_event())).state is WorkflowState.DEAD_LETTERED


@pytest.mark.asyncio
async def test_conflicting_idempotency_identity_is_quarantined_without_second_call() -> None:
    runner = RecordingPipelineRunner()
    store = InMemoryIdempotencyStore()
    workflow = GovernedIngestionWorkflow(
        malware_scanner=FakeMalwareScanner(MalwareStatus.CLEAN, FIXED_NOW),
        idempotency_store=store,
        audit_sink=RecordingAuditSink(),
        pipeline_runner=runner,
        clock=lambda: FIXED_NOW,
    )
    first = make_event(idempotency_key="d" * 64)
    conflict = make_event(idempotency_key="d" * 64, content_hash="e" * 64)
    assert (await workflow.process(first)).state is WorkflowState.INDEXED
    assert (await workflow.process(conflict)).state is WorkflowState.QUARANTINED
    assert len(runner.calls) == 1


@pytest.mark.asyncio
async def test_scanner_error_fails_closed_before_eligibility() -> None:
    runner = RecordingPipelineRunner()
    workflow = GovernedIngestionWorkflow(
        malware_scanner=FakeMalwareScanner(MalwareStatus.CLEAN, FIXED_NOW, fail=True),
        idempotency_store=InMemoryIdempotencyStore(),
        audit_sink=RecordingAuditSink(),
        pipeline_runner=runner,
        clock=lambda: FIXED_NOW,
    )
    result = await workflow.process(make_event())
    assert result.reason_code == "MALWARE_ERROR"
    assert runner.calls == []
