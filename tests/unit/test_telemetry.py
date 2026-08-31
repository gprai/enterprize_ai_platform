"""Unit tests for bounded, content-free W4-003 telemetry primitives."""

from __future__ import annotations

from typing import cast
from uuid import UUID

import pytest
from opentelemetry.sdk.trace import ReadableSpan

from enterprise_ai_platform.telemetry.models import (
    LOG_CAPACITY,
    METRIC_NAMES,
    METRIC_SERIES_UPPER_BOUND,
    SPAN_CAPACITY,
    SafeLogRecord,
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import (
    BoundedInMemoryLogSink,
    BoundedInMemorySpanExporter,
    NullTelemetryRuntime,
    telemetry_for_application,
)


def _record(sequence: int) -> SafeLogRecord:
    return SafeLogRecord(
        timestamp_unix_nano=sequence,
        event_name=TelemetryEventName.STAGE_COMPLETED,
        service_name="enterprise-ai-api",
        request_id=UUID("00000000-0000-4000-8000-000000000001"),
        stage=TelemetryStage.API,
        operation=TelemetryOperation.REQUEST,
        outcome=TelemetryOutcome.SUCCESS,
    )


def test_exact_metric_names_are_stable_and_unique() -> None:
    assert METRIC_NAMES == {
        "stage_executions": "enterprise_ai.stage.executions",
        "stage_duration": "enterprise_ai.stage.duration",
        "usage_tokens": "enterprise_ai.usage.tokens",
        "retrieval_results": "enterprise_ai.retrieval.results",
        "agent_steps": "enterprise_ai.agent.steps",
        "agent_tool_calls": "enterprise_ai.agent.tool.calls",
        "export_failures": "enterprise_ai.telemetry.export.failures",
        "dropped": "enterprise_ai.telemetry.dropped",
    }
    assert len(METRIC_NAMES.values()) == len(set(METRIC_NAMES.values())) == 8
    assert 0 < METRIC_SERIES_UPPER_BOUND < 2**63


def test_null_runtime_is_side_effect_free_and_lifecycle_safe() -> None:
    runtime = NullTelemetryRuntime()

    with runtime.start_scope(
        TelemetryStage.API,
        TelemetryOperation.REQUEST,
    ) as scope:
        scope.finish(TelemetryOutcome.SUCCESS)

    runtime.record_tokens(
        stage=TelemetryStage.LLM,
        operation=TelemetryOperation.CHAT,
        input_tokens=1,
        output_tokens=2,
        total_tokens=3,
    )
    runtime.record_retrieval_results(2)
    runtime.record_agent_steps(
        3,
        outcome=TelemetryOutcome.SUCCESS,
        terminal_reason="answer_reference_ready",
    )
    runtime.record_tool_call(
        tool_name="get_service_status",
        tool_version="1.0",
        outcome=TelemetryOutcome.SUCCESS,
    )

    assert runtime.force_flush() is True
    assert runtime.shutdown() is True


def test_bounded_span_exporter_drops_oldest_at_exact_capacity() -> None:
    exporter = BoundedInMemorySpanExporter()
    spans = [cast(ReadableSpan, object()) for _ in range(SPAN_CAPACITY + 1)]
    dropped: list[int] = []
    exporter.set_drop_callback(dropped.append)

    exporter.export(spans)

    assert exporter.get_finished_spans() == tuple(spans[1:])
    assert dropped == [1]
    assert len(exporter.get_finished_spans()) == SPAN_CAPACITY == 512


def test_bounded_log_sink_drops_oldest_at_exact_capacity() -> None:
    sink = BoundedInMemoryLogSink()
    dropped = [sink.emit(_record(index)) for index in range(LOG_CAPACITY + 1)]

    records = sink.records()
    assert dropped.count(1) == 1
    assert len(records) == LOG_CAPACITY == 512
    assert records[0].timestamp_unix_nano == 1
    assert records[-1].timestamp_unix_nano == LOG_CAPACITY


@pytest.mark.parametrize("capacity", [0, 511, 513])
def test_buffers_reject_any_unapproved_capacity(capacity: int) -> None:
    with pytest.raises(ValueError, match="exactly 512"):
        BoundedInMemorySpanExporter(capacity)
    with pytest.raises(ValueError, match="exactly 512"):
        BoundedInMemoryLogSink(capacity)


def test_runtime_selection_requires_explicit_enabled_injection() -> None:
    runtime = NullTelemetryRuntime()

    assert isinstance(
        telemetry_for_application(enabled=False, injected=None),
        NullTelemetryRuntime,
    )
    assert telemetry_for_application(enabled=True, injected=runtime) is runtime
    with pytest.raises(ValueError, match="disabled telemetry"):
        telemetry_for_application(enabled=False, injected=runtime)
    with pytest.raises(ValueError, match="requires an injected runtime"):
        telemetry_for_application(enabled=True, injected=None)


def test_metric_attributes_never_include_correlation_or_identity() -> None:
    labels = SafeTelemetryAttributes(
        stage=TelemetryStage.RETRIEVAL,
        operation=TelemetryOperation.RETRIEVE,
        outcome=TelemetryOutcome.SUCCESS,
    ).metric_attributes()

    assert labels == {
        "stage": "retrieval",
        "operation": "retrieve",
        "outcome": "success",
    }
    forbidden = {
        "request_id",
        "trace_id",
        "span_id",
        "tenant_id",
        "subject_id",
        "approval_id",
        "query",
        "source_id",
    }
    assert forbidden.isdisjoint(labels)
