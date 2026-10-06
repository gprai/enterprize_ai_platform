"""Bounded, synchronous and failure-isolated telemetry runtime."""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from contextvars import ContextVar, Token
from dataclasses import dataclass
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, Protocol, Self
from uuid import UUID

from opentelemetry import trace
from opentelemetry.context import Context
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.trace import Span, Status, StatusCode
from pydantic import ValidationError

from enterprise_ai_platform import __version__
from enterprise_ai_platform.config import Settings

from .models import (
    LOG_CAPACITY,
    METRIC_NAMES,
    SPAN_CAPACITY,
    SPAN_NAMES,
    DropReason,
    SafeLogRecord,
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetrySignal,
    TelemetryStage,
    TokenType,
)

if TYPE_CHECKING:
    from enterprise_ai_platform.embeddings.base import EmbeddingMetric

_request_id_context: ContextVar[UUID | None] = ContextVar(
    "enterprise_ai_request_id",
    default=None,
)


class TelemetryScope(Protocol):
    def __enter__(self) -> TelemetryScope: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]: ...

    def finish(
        self,
        outcome: TelemetryOutcome,
        *,
        terminal_reason: str | None = None,
        safe_error_code: str | None = None,
    ) -> None: ...


class TelemetryRuntime(Protocol):
    def start_scope(
        self,
        stage: TelemetryStage,
        operation: TelemetryOperation,
        *,
        request_id: UUID | None = None,
        root: bool = False,
        prompt_version: str | None = None,
        graph_version: str | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
    ) -> TelemetryScope: ...

    def record_tokens(
        self,
        *,
        stage: TelemetryStage,
        operation: TelemetryOperation,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int,
        prompt_version: str | None = None,
    ) -> None: ...

    def record_retrieval_results(self, count: int) -> None: ...

    def record_agent_steps(
        self,
        count: int,
        *,
        outcome: TelemetryOutcome,
        terminal_reason: str | None,
    ) -> None: ...

    def record_tool_call(
        self,
        *,
        tool_name: str,
        tool_version: str,
        outcome: TelemetryOutcome,
    ) -> None: ...

    def emit_event(
        self,
        event_name: TelemetryEventName,
        attributes: SafeTelemetryAttributes,
        *,
        duration_ms: float | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        total_tokens: int | None = None,
        result_count: int | None = None,
        step_count: int | None = None,
        tool_call_count: int | None = None,
    ) -> None: ...

    def force_flush(self) -> bool: ...

    def shutdown(self) -> bool: ...


class SafeLogSink(Protocol):
    def emit(self, record: SafeLogRecord) -> int: ...


class NullTelemetryScope:
    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        return False

    def finish(
        self,
        outcome: TelemetryOutcome,
        *,
        terminal_reason: str | None = None,
        safe_error_code: str | None = None,
    ) -> None:
        del outcome, terminal_reason, safe_error_code


class NullTelemetryRuntime:
    """Default offline runtime with no providers, buffers or side effects."""

    def start_scope(
        self,
        stage: TelemetryStage,
        operation: TelemetryOperation,
        *,
        request_id: UUID | None = None,
        root: bool = False,
        prompt_version: str | None = None,
        graph_version: str | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
    ) -> NullTelemetryScope:
        del (
            stage,
            operation,
            request_id,
            root,
            prompt_version,
            graph_version,
            tool_name,
            tool_version,
        )
        return NullTelemetryScope()

    def record_tokens(
        self,
        *,
        stage: TelemetryStage,
        operation: TelemetryOperation,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int,
        prompt_version: str | None = None,
    ) -> None:
        del stage, operation, input_tokens, output_tokens, total_tokens, prompt_version

    def record_retrieval_results(self, count: int) -> None:
        del count

    def record_agent_steps(
        self,
        count: int,
        *,
        outcome: TelemetryOutcome,
        terminal_reason: str | None,
    ) -> None:
        del count, outcome, terminal_reason

    def record_tool_call(
        self,
        *,
        tool_name: str,
        tool_version: str,
        outcome: TelemetryOutcome,
    ) -> None:
        del tool_name, tool_version, outcome

    def emit_event(
        self,
        event_name: TelemetryEventName,
        attributes: SafeTelemetryAttributes,
        *,
        duration_ms: float | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        total_tokens: int | None = None,
        result_count: int | None = None,
        step_count: int | None = None,
        tool_call_count: int | None = None,
    ) -> None:
        del (
            event_name,
            attributes,
            duration_ms,
            input_tokens,
            output_tokens,
            total_tokens,
            result_count,
            step_count,
            tool_call_count,
        )

    def force_flush(self) -> bool:
        return True

    def shutdown(self) -> bool:
        return True


class BoundedInMemorySpanExporter(SpanExporter):
    """Retain a fixed number of completed spans and drop the oldest first."""

    def __init__(self, capacity: int = SPAN_CAPACITY) -> None:
        if capacity != SPAN_CAPACITY:
            raise ValueError("span capacity must remain exactly 512")
        self._spans: deque[ReadableSpan] = deque(maxlen=capacity)
        self._lock = threading.Lock()
        self._on_drop: Callable[[int], None] | None = None
        self._shutdown = False

    def set_drop_callback(self, callback: Callable[[int], None]) -> None:
        self._on_drop = callback

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        dropped = 0
        with self._lock:
            if self._shutdown:
                return SpanExportResult.FAILURE
            for span in spans:
                if len(self._spans) == self._spans.maxlen:
                    dropped += 1
                self._spans.append(span)
        if dropped and self._on_drop is not None:
            try:
                self._on_drop(dropped)
            except Exception:
                return SpanExportResult.SUCCESS
        return SpanExportResult.SUCCESS

    def get_finished_spans(self) -> tuple[ReadableSpan, ...]:
        with self._lock:
            return tuple(self._spans)

    def clear(self) -> None:
        with self._lock:
            self._spans.clear()

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        return timeout_millis >= 0

    def shutdown(self) -> None:
        with self._lock:
            self._shutdown = True


class SafeSpanExporter(SpanExporter):
    """Normalize exporter failures before the SDK can log raw exceptions."""

    def __init__(
        self,
        delegate: SpanExporter,
        on_failure: Callable[[], None],
    ) -> None:
        self._delegate = delegate
        self._on_failure = on_failure

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        try:
            result = self._delegate.export(spans)
        except Exception:
            self._safe_failure_signal()
            return SpanExportResult.FAILURE
        if result is SpanExportResult.FAILURE:
            self._safe_failure_signal()
        return result

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        try:
            flushed = self._delegate.force_flush(timeout_millis)
        except Exception:
            self._safe_failure_signal()
            return False
        if not flushed:
            self._safe_failure_signal()
        return flushed

    def shutdown(self) -> None:
        try:
            self._delegate.shutdown()
        except Exception:
            self._safe_failure_signal()

    def _safe_failure_signal(self) -> None:
        try:
            self._on_failure()
        except Exception:
            return


class BoundedInMemoryLogSink:
    """Thread-safe, fixed-capacity sink for validated structured metadata."""

    def __init__(self, capacity: int = LOG_CAPACITY) -> None:
        if capacity != LOG_CAPACITY:
            raise ValueError("log capacity must remain exactly 512")
        self._records: deque[SafeLogRecord] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def emit(self, record: SafeLogRecord) -> int:
        with self._lock:
            dropped = int(len(self._records) == self._records.maxlen)
            self._records.append(record)
            return dropped

    def records(self) -> tuple[SafeLogRecord, ...]:
        with self._lock:
            return tuple(self._records)

    def clear(self) -> None:
        with self._lock:
            self._records.clear()


class _OpenTelemetryScope:
    def __init__(
        self,
        runtime: OpenTelemetryRuntime,
        attributes: SafeTelemetryAttributes,
        *,
        request_id: UUID | None,
        root: bool,
    ) -> None:
        self._runtime = runtime
        self._attributes = attributes
        self._request_id = request_id
        self._root = root
        self._manager: object | None = None
        self._span: Span | None = None
        self._request_token: Token[UUID | None] | None = None
        self._started = 0.0
        self._outcome = TelemetryOutcome.SUCCESS
        self._terminal_reason: str | None = None
        self._safe_error_code: str | None = None

    def __enter__(self) -> Self:
        self._started = self._runtime.monotonic()
        try:
            if self._request_id is not None:
                self._request_token = _request_id_context.set(self._request_id)
            context = Context() if self._root else None
            span_name = SPAN_NAMES[(self._attributes.stage, self._attributes.operation)]
            manager = self._runtime.tracer.start_as_current_span(
                span_name,
                context=context,
                attributes=self._attributes.metric_attributes(),
                record_exception=False,
                set_status_on_exception=False,
            )
            self._manager = manager
            self._span = manager.__enter__()
        except Exception:
            self._runtime._safe_export_failure()
        return self

    def finish(
        self,
        outcome: TelemetryOutcome,
        *,
        terminal_reason: str | None = None,
        safe_error_code: str | None = None,
    ) -> None:
        self._outcome = outcome
        self._terminal_reason = terminal_reason
        self._safe_error_code = safe_error_code

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        del exc_value, traceback
        if exc_type is not None:
            if issubclass(exc_type, asyncio.CancelledError):
                self._outcome = TelemetryOutcome.CANCELLED
            elif issubclass(exc_type, TimeoutError):
                self._outcome = TelemetryOutcome.TIMEOUT
            else:
                self._outcome = TelemetryOutcome.ERROR
                self._safe_error_code = "internal_error"
        try:
            elapsed_seconds = max(
                0.0,
                self._runtime.monotonic() - self._started,
            )
            completed = self._attributes.model_copy(
                update={
                    "outcome": self._outcome,
                    "terminal_reason": self._terminal_reason,
                    "safe_error_code": self._safe_error_code,
                }
            )
            try:
                completed = SafeTelemetryAttributes.model_validate(
                    completed.model_dump(mode="python"),
                    strict=True,
                )
            except ValidationError:
                completed = SafeTelemetryAttributes(
                    stage=TelemetryStage.TELEMETRY,
                    operation=TelemetryOperation.EXPORT,
                    outcome=TelemetryOutcome.ERROR,
                    safe_error_code="telemetry_observation_invalid",
                )
            if self._span is not None:
                for key, value in completed.metric_attributes().items():
                    self._span.set_attribute(key, value)
                if completed.outcome in {
                    TelemetryOutcome.ERROR,
                    TelemetryOutcome.TIMEOUT,
                }:
                    self._span.set_status(Status(StatusCode.ERROR))
            self._runtime._record_stage(completed, elapsed_seconds, self._span)
        except Exception:
            self._runtime._safe_export_failure()
        finally:
            if self._manager is not None:
                try:
                    self._manager.__exit__(None, None, None)  # type: ignore[attr-defined]
                except Exception:
                    self._runtime._safe_export_failure()
            if self._request_token is not None:
                _request_id_context.reset(self._request_token)
        return False


class OpenTelemetryRuntime:
    """Explicit provider-backed runtime with synchronous bounded processing."""

    def __init__(
        self,
        *,
        service_name: str,
        tracer_provider: TracerProvider,
        meter_provider: MeterProvider,
        log_sink: BoundedInMemoryLogSink,
        export_sink: SafeLogSink | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        unix_time_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        self.service_name = service_name
        self.tracer = tracer_provider.get_tracer("enterprise_ai_platform.telemetry")
        self.meter = meter_provider.get_meter("enterprise_ai_platform.telemetry")
        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider
        self._log_sink = log_sink
        self._export_sink = export_sink
        self.monotonic = monotonic
        self._unix_time_ns = unix_time_ns
        self._lifecycle_lock = threading.Lock()
        self._shutdown = False
        self._stage_executions = self.meter.create_counter(
            METRIC_NAMES["stage_executions"],
            unit="{execution}",
        )
        self._stage_duration = self.meter.create_histogram(
            METRIC_NAMES["stage_duration"],
            unit="s",
        )
        self._usage_tokens = self.meter.create_counter(
            METRIC_NAMES["usage_tokens"],
            unit="{token}",
        )
        self._retrieval_results = self.meter.create_histogram(
            METRIC_NAMES["retrieval_results"],
            unit="{item}",
        )
        self._agent_steps = self.meter.create_histogram(
            METRIC_NAMES["agent_steps"],
            unit="{step}",
        )
        self._agent_tool_calls = self.meter.create_counter(
            METRIC_NAMES["agent_tool_calls"],
            unit="{call}",
        )
        self._export_failures = self.meter.create_counter(
            METRIC_NAMES["export_failures"],
            unit="{failure}",
        )
        self._dropped = self.meter.create_counter(
            METRIC_NAMES["dropped"],
            unit="{item}",
        )

    @property
    def log_sink(self) -> BoundedInMemoryLogSink:
        return self._log_sink

    def start_scope(
        self,
        stage: TelemetryStage,
        operation: TelemetryOperation,
        *,
        request_id: UUID | None = None,
        root: bool = False,
        prompt_version: str | None = None,
        graph_version: str | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
    ) -> TelemetryScope:
        try:
            attributes = SafeTelemetryAttributes(
                stage=stage,
                operation=operation,
                prompt_version=prompt_version,
                graph_version=graph_version,
                tool_name=tool_name,
                tool_version=tool_version,
            )
        except ValidationError:
            self._safe_invalid_observation()
            return NullTelemetryScope()
        return _OpenTelemetryScope(
            self,
            attributes,
            request_id=request_id,
            root=root,
        )

    def _record_stage(
        self,
        attributes: SafeTelemetryAttributes,
        elapsed_seconds: float,
        span: Span | None,
    ) -> None:
        labels = attributes.metric_attributes()
        self._stage_executions.add(1, labels)
        self._stage_duration.record(elapsed_seconds, labels)
        trace_id: str | None = None
        span_id: str | None = None
        if span is not None and span.get_span_context().is_valid:
            context = span.get_span_context()
            trace_id = f"{context.trace_id:032x}"
            span_id = f"{context.span_id:016x}"
        self.emit_event(
            TelemetryEventName.STAGE_COMPLETED,
            attributes,
            duration_ms=elapsed_seconds * 1000,
            trace_id=trace_id,
            span_id=span_id,
        )

    def emit_event(
        self,
        event_name: TelemetryEventName,
        attributes: SafeTelemetryAttributes,
        *,
        duration_ms: float | None = None,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        total_tokens: int | None = None,
        result_count: int | None = None,
        step_count: int | None = None,
        tool_call_count: int | None = None,
        trace_id: str | None = None,
        span_id: str | None = None,
    ) -> None:
        try:
            outcome = attributes.outcome or TelemetryOutcome.SUCCESS
            active_span = trace.get_current_span()
            if trace_id is None and active_span.get_span_context().is_valid:
                context = active_span.get_span_context()
                trace_id = f"{context.trace_id:032x}"
                span_id = f"{context.span_id:016x}"
            event_attributes: dict[str, str | int | float] = {**attributes.metric_attributes()}
            for key, value in (
                ("duration_ms", duration_ms),
                ("input_tokens", input_tokens),
                ("output_tokens", output_tokens),
                ("total_tokens", total_tokens),
                ("result_count", result_count),
                ("step_count", step_count),
                ("tool_call_count", tool_call_count),
            ):
                if value is not None:
                    event_attributes[key] = value
            if active_span.get_span_context().is_valid:
                active_span.add_event(
                    event_name.value,
                    attributes=event_attributes,
                )
            record = SafeLogRecord(
                timestamp_unix_nano=self._unix_time_ns(),
                event_name=event_name,
                service_name=self.service_name,
                request_id=_request_id_context.get(),
                trace_id=trace_id,
                span_id=span_id,
                stage=attributes.stage,
                operation=attributes.operation,
                outcome=outcome,
                terminal_reason=attributes.terminal_reason,
                safe_error_code=attributes.safe_error_code,
                duration_ms=duration_ms,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                result_count=result_count,
                step_count=step_count,
                tool_call_count=tool_call_count,
                prompt_version=attributes.prompt_version,
                graph_version=attributes.graph_version,
                tool_name=attributes.tool_name,
                tool_version=attributes.tool_version,
            )
            dropped = self._log_sink.emit(record)
            if dropped:
                self._record_drop(TelemetrySignal.LOG, dropped)
            if (
                self._export_sink is not None
                and event_name is not TelemetryEventName.EXPORT_FAILURE
            ):
                self._export_sink.emit(record)
        except Exception:
            self._safe_invalid_observation()

    def record_tokens(
        self,
        *,
        stage: TelemetryStage,
        operation: TelemetryOperation,
        input_tokens: int,
        output_tokens: int,
        total_tokens: int,
        prompt_version: str | None = None,
    ) -> None:
        if min(input_tokens, output_tokens, total_tokens) < 0:
            self._record_invalid_observation()
            return
        for token_type, value in (
            (TokenType.INPUT, input_tokens),
            (TokenType.OUTPUT, output_tokens),
            (TokenType.TOTAL, total_tokens),
        ):
            attributes = SafeTelemetryAttributes(
                stage=stage,
                operation=operation,
                outcome=TelemetryOutcome.SUCCESS,
                token_type=token_type,
                prompt_version=prompt_version,
            )
            self._usage_tokens.add(value, attributes.metric_attributes())
        self.emit_event(
            TelemetryEventName.STAGE_COMPLETED,
            SafeTelemetryAttributes(
                stage=stage,
                operation=operation,
                outcome=TelemetryOutcome.SUCCESS,
                prompt_version=prompt_version,
            ),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
        )

    def record_retrieval_results(self, count: int) -> None:
        if count < 0:
            self._record_invalid_observation()
            return
        attributes = SafeTelemetryAttributes(
            stage=TelemetryStage.RETRIEVAL,
            operation=TelemetryOperation.RETRIEVE,
            outcome=TelemetryOutcome.SUCCESS,
        )
        self._retrieval_results.record(count, attributes.metric_attributes())

    def record_agent_steps(
        self,
        count: int,
        *,
        outcome: TelemetryOutcome,
        terminal_reason: str | None,
    ) -> None:
        if not 0 <= count <= 8:
            self._record_invalid_observation()
            return
        attributes = SafeTelemetryAttributes(
            stage=TelemetryStage.AGENT,
            operation=TelemetryOperation.HANDLE,
            outcome=outcome,
            terminal_reason=terminal_reason,
            graph_version="w4-002.graph.v1",
        )
        self._agent_steps.record(count, attributes.metric_attributes())
        self.emit_event(
            TelemetryEventName.STAGE_COMPLETED,
            attributes,
            step_count=count,
        )

    def record_tool_call(
        self,
        *,
        tool_name: str,
        tool_version: str,
        outcome: TelemetryOutcome,
    ) -> None:
        try:
            attributes = SafeTelemetryAttributes(
                stage=TelemetryStage.TOOL,
                operation=TelemetryOperation.EXECUTE_TOOL,
                outcome=outcome,
                tool_name=tool_name,
                tool_version=tool_version,
            )
        except ValidationError:
            self._record_invalid_observation()
            return
        self._agent_tool_calls.add(1, attributes.metric_attributes())
        self.emit_event(
            TelemetryEventName.STAGE_COMPLETED,
            attributes,
            tool_call_count=1,
        )

    def _record_invalid_observation(self) -> None:
        self._record_drop(TelemetrySignal.LOG, 1, DropReason.INVALID_OBSERVATION)

    def _safe_invalid_observation(self) -> None:
        try:
            self._record_invalid_observation()
        except Exception:
            return

    def _safe_export_failure(self) -> None:
        try:
            self.record_export_failure()
        except Exception:
            return

    def _record_drop(
        self,
        signal: TelemetrySignal,
        count: int,
        reason: DropReason = DropReason.CAPACITY,
    ) -> None:
        attributes = SafeTelemetryAttributes(
            stage=TelemetryStage.TELEMETRY,
            operation=TelemetryOperation.EXPORT,
            outcome=TelemetryOutcome.ERROR,
            safe_error_code="telemetry_capacity_exceeded",
            signal=signal,
            drop_reason=reason,
        )
        self._dropped.add(count, attributes.metric_attributes())

    def record_span_drop(self, count: int) -> None:
        self._record_drop(TelemetrySignal.TRACE, count)
        self.emit_event(
            TelemetryEventName.RECORD_DROPPED,
            SafeTelemetryAttributes(
                stage=TelemetryStage.TELEMETRY,
                operation=TelemetryOperation.EXPORT,
                outcome=TelemetryOutcome.ERROR,
                safe_error_code="telemetry_capacity_exceeded",
                signal=TelemetrySignal.TRACE,
                drop_reason=DropReason.CAPACITY,
            ),
        )

    def record_export_drop(self, signal: TelemetrySignal, count: int) -> None:
        self._record_drop(signal, count)

    def record_export_failure(self) -> None:
        attributes = SafeTelemetryAttributes(
            stage=TelemetryStage.TELEMETRY,
            operation=TelemetryOperation.EXPORT,
            outcome=TelemetryOutcome.ERROR,
            safe_error_code="telemetry_export_failed",
            signal=TelemetrySignal.TRACE,
            drop_reason=DropReason.EXPORT_FAILURE,
        )
        self._export_failures.add(1, attributes.metric_attributes())
        self.emit_event(TelemetryEventName.EXPORT_FAILURE, attributes)

    def force_flush(self) -> bool:
        with self._lifecycle_lock:
            if self._shutdown:
                return False
            try:
                trace_ok = self._tracer_provider.force_flush(timeout_millis=1000)
                metric_ok = self._meter_provider.force_flush(timeout_millis=1000)
                sink_flush = getattr(self._export_sink, "force_flush", None)
                log_ok = True if sink_flush is None else bool(sink_flush())
            except Exception:
                self._safe_export_failure()
                return False
            return bool(trace_ok and metric_ok and log_ok)

    def shutdown(self) -> bool:
        with self._lifecycle_lock:
            if self._shutdown:
                return False
            self._shutdown = True
        try:
            self._tracer_provider.shutdown()
            self._meter_provider.shutdown()
            sink_shutdown = getattr(self._export_sink, "shutdown", None)
            if sink_shutdown is not None:
                sink_shutdown()
        except Exception:
            self._safe_export_failure()
            return False
        return True


@dataclass(frozen=True, slots=True)
class InMemoryTelemetryComposition:
    runtime: OpenTelemetryRuntime
    span_exporter: SpanExporter
    metric_reader: InMemoryMetricReader
    log_sink: BoundedInMemoryLogSink


class _OTLPSafeLogSink:
    """Emit only schema-validated, content-free records through OTLP logs."""

    def __init__(self, handler: logging.Handler, provider: Any) -> None:
        self._handler = handler
        self._provider = provider
        self._lock = threading.Lock()
        self._shutdown = False

    def emit(self, record: SafeLogRecord) -> int:
        with self._lock:
            if self._shutdown:
                return 1
        python_record = logging.LogRecord(
            name="enterprise_ai_platform.telemetry",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg=record.event_name.value,
            args=(),
            exc_info=None,
        )
        for key, value in record.model_dump(mode="json", exclude_none=True).items():
            if key not in {"event_name", "service_name", "schema_version"}:
                setattr(python_record, f"enterprise_ai_{key}", value)
        self._handler.emit(python_record)
        return 0

    def force_flush(self) -> bool:
        return bool(self._provider.force_flush(timeout_millis=1000))

    def shutdown(self) -> None:
        with self._lock:
            if self._shutdown:
                return
            self._shutdown = True
        self._handler.close()
        self._provider.shutdown()


class OTLPTelemetryRuntime(OpenTelemetryRuntime):
    """Marker runtime for the bounded pod-local OTLP composition."""


@dataclass(frozen=True, slots=True)
class OTLPTelemetryComposition:
    runtime: OTLPTelemetryRuntime
    log_sink: _OTLPSafeLogSink


def build_otlp_telemetry(*, settings: Settings) -> OTLPTelemetryComposition:
    """Build bounded trace, metric and safe-log exporters for the loopback sidecar."""

    if (
        settings.telemetry_exporter != "otlp_grpc"
        or settings.telemetry_otlp_endpoint != "http://127.0.0.1:4317"
    ):
        raise ValueError("OTLP telemetry requires the exact approved loopback profile")

    from opentelemetry.exporter.otlp.proto.grpc._log_exporter import (  # type: ignore[import-not-found]
        OTLPLogExporter,
    )
    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (  # type: ignore[import-not-found]
        OTLPMetricExporter,
    )
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (  # type: ignore[import-not-found]
        OTLPSpanExporter,
    )
    from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
    from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
    from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

    resource = Resource(
        attributes={
            "service.name": settings.telemetry_service_name,
            "service.version": __version__,
            "deployment.environment.name": settings.environment,
        }
    )
    endpoint = settings.telemetry_otlp_endpoint
    tracer_provider = TracerProvider(resource=resource)
    span_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True, timeout=1.0)
    tracer_provider.add_span_processor(
        BatchSpanProcessor(
            span_exporter,
            max_queue_size=512,
            schedule_delay_millis=1000,
            max_export_batch_size=64,
            export_timeout_millis=1000,
        )
    )
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(endpoint=endpoint, insecure=True, timeout=1.0),
        export_interval_millis=1000,
        export_timeout_millis=1000,
    )
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    logger_provider = LoggerProvider(resource=resource, shutdown_on_exit=False)
    logger_provider.add_log_record_processor(
        BatchLogRecordProcessor(
            OTLPLogExporter(endpoint=endpoint, insecure=True, timeout=1.0),
            max_queue_size=512,
            schedule_delay_millis=1000,
            max_export_batch_size=64,
            export_timeout_millis=1000,
        )
    )
    log_sink = _OTLPSafeLogSink(
        LoggingHandler(level=logging.INFO, logger_provider=logger_provider),
        logger_provider,
    )
    local_log_sink = BoundedInMemoryLogSink()
    runtime = OTLPTelemetryRuntime(
        service_name=settings.telemetry_service_name,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        log_sink=local_log_sink,
        export_sink=log_sink,
    )
    return OTLPTelemetryComposition(runtime=runtime, log_sink=log_sink)


def build_in_memory_telemetry(
    *,
    settings: Settings,
    monotonic: Callable[[], float] = time.monotonic,
    unix_time_ns: Callable[[], int] = time.time_ns,
    span_exporter: SpanExporter | None = None,
    export_sink: SafeLogSink | None = None,
) -> InMemoryTelemetryComposition:
    """Create an explicit local-only composition with no network exporter."""

    resource = Resource(
        attributes={
            "service.name": settings.telemetry_service_name,
            "service.version": __version__,
            "deployment.environment.name": settings.environment,
        }
    )
    bounded_exporter = span_exporter or BoundedInMemorySpanExporter()
    tracer_provider = TracerProvider(resource=resource)
    metric_reader = InMemoryMetricReader()
    meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
    log_sink = BoundedInMemoryLogSink()
    runtime = OpenTelemetryRuntime(
        service_name=settings.telemetry_service_name,
        tracer_provider=tracer_provider,
        meter_provider=meter_provider,
        log_sink=log_sink,
        export_sink=export_sink,
        monotonic=monotonic,
        unix_time_ns=unix_time_ns,
    )
    if isinstance(bounded_exporter, BoundedInMemorySpanExporter):
        bounded_exporter.set_drop_callback(runtime.record_span_drop)
    tracer_provider.add_span_processor(
        SimpleSpanProcessor(SafeSpanExporter(bounded_exporter, runtime.record_export_failure))
    )
    return InMemoryTelemetryComposition(
        runtime=runtime,
        span_exporter=bounded_exporter,
        metric_reader=metric_reader,
        log_sink=log_sink,
    )


class EmbeddingTelemetryRecorder:
    """Adapt the existing aggregate embedding metric without accepting text."""

    def __init__(self, telemetry: TelemetryRuntime) -> None:
        self._telemetry = telemetry

    def record(self, metric: EmbeddingMetric) -> None:
        operation = (
            TelemetryOperation.EMBED_QUERY
            if metric.operation == "query"
            else TelemetryOperation.EMBED_DOCUMENTS
        )
        outcome = (
            TelemetryOutcome.SUCCESS if metric.outcome == "success" else TelemetryOutcome.ERROR
        )
        with self._telemetry.start_scope(TelemetryStage.EMBEDDING, operation) as scope:
            scope.finish(outcome)


def telemetry_for_application(
    *,
    enabled: bool,
    injected: TelemetryRuntime | None,
) -> TelemetryRuntime:
    """Return the null runtime by default and require explicit enabled injection."""

    if not enabled:
        if injected is not None:
            raise ValueError("disabled telemetry cannot accept an active runtime")
        return NullTelemetryRuntime()
    if injected is None:
        raise ValueError("enabled telemetry requires an injected runtime")
    return injected
