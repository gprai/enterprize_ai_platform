"""Bounded, single-worker export boundary for validated W6-002 observations."""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from enterprise_ai_platform.config import Settings

from .ai_operations import AIOperationsObservation
from .models import (
    RuntimeConfigurationHashes,
    SafeLogRecord,
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetrySignal,
    TelemetryStage,
)
from .runtime import (
    InMemoryTelemetryComposition,
    TelemetryRuntime,
    TelemetryScope,
    build_in_memory_telemetry,
)

EXPORT_QUEUE_CAPACITY = 512
EXPORT_BATCH_SIZE = 64
EXPORT_DELAY_SECONDS = 1.0
EXPORT_TIMEOUT_SECONDS = 1.0
EXPORT_FLUSH_TIMEOUT_SECONDS = 2.0
EXPORT_SHUTDOWN_TIMEOUT_SECONDS = 2.0


class ExportSink(Protocol):
    def export(self, records: tuple[SafeLogRecord, ...], *, timeout_seconds: float) -> bool: ...

    def shutdown(self) -> bool: ...


class BoundedExportQueue:
    """Drop-oldest queue whose single worker never retries business operations."""

    def __init__(self, sink: ExportSink) -> None:
        self._sink = sink
        self._records: deque[SafeLogRecord] = deque(maxlen=EXPORT_QUEUE_CAPACITY)
        self._condition = threading.Condition()
        self._accepting = True
        self._stop = False
        self._inflight = False
        self._on_drop: Callable[[TelemetrySignal, int], None] | None = None
        self._on_failure: Callable[[], None] | None = None
        self._worker = threading.Thread(
            target=self._run,
            name="w6-002-telemetry-export",
            daemon=True,
        )

    def bind_callbacks(
        self,
        *,
        on_drop: Callable[[TelemetrySignal, int], None],
        on_failure: Callable[[], None],
    ) -> None:
        self._on_drop = on_drop
        self._on_failure = on_failure

    def start(self) -> None:
        self._worker.start()

    def emit(self, record: SafeLogRecord) -> int:
        with self._condition:
            if not self._accepting:
                return 1
            dropped = int(len(self._records) == EXPORT_QUEUE_CAPACITY)
            if dropped:
                self._records.popleft()
            self._records.append(record)
            self._condition.notify()
        if dropped and self._on_drop is not None:
            self._on_drop(TelemetrySignal.LOG, dropped)
        return dropped

    def records(self) -> tuple[SafeLogRecord, ...]:
        with self._condition:
            return tuple(self._records)

    def clear(self) -> None:
        with self._condition:
            self._records.clear()
            self._condition.notify_all()

    def force_flush(self, timeout_seconds: float = EXPORT_FLUSH_TIMEOUT_SECONDS) -> bool:
        deadline = time.monotonic() + timeout_seconds
        with self._condition:
            self._condition.notify_all()
            while self._records or self._inflight:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(remaining)
        return True

    def shutdown(self) -> bool:
        with self._condition:
            if not self._accepting:
                return False
            self._accepting = False
        flushed = self.force_flush()
        with self._condition:
            self._stop = True
            self._condition.notify_all()
        self._worker.join(EXPORT_SHUTDOWN_TIMEOUT_SECONDS)
        try:
            sink_ok = self._sink.shutdown()
        except Exception:
            sink_ok = False
        return flushed and not self._worker.is_alive() and sink_ok

    def _run(self) -> None:
        while True:
            with self._condition:
                if not self._records and not self._stop:
                    self._condition.wait(EXPORT_DELAY_SECONDS)
                if self._stop and not self._records:
                    self._condition.notify_all()
                    return
                if not self._records:
                    continue
                batch = tuple(
                    self._records.popleft()
                    for _ in range(min(EXPORT_BATCH_SIZE, len(self._records)))
                )
                self._inflight = True
            try:
                succeeded = self._sink.export(batch, timeout_seconds=EXPORT_TIMEOUT_SECONDS)
            except Exception:
                succeeded = False
            if not succeeded and self._on_failure is not None:
                try:
                    self._on_failure()
                except Exception:
                    self._on_failure = None
            with self._condition:
                self._inflight = False
                self._condition.notify_all()


class ExportingTelemetryRuntime:
    """Own one export queue while preserving the existing runtime protocol."""

    def __init__(self, delegate: TelemetryRuntime, queue: BoundedExportQueue) -> None:
        self._delegate = delegate
        self._queue = queue
        self._lock = threading.Lock()
        self._shutdown = False

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
        return self._delegate.start_scope(
            stage,
            operation,
            request_id=request_id,
            root=root,
            prompt_version=prompt_version,
            graph_version=graph_version,
            tool_name=tool_name,
            tool_version=tool_version,
        )

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
        self._delegate.record_tokens(
            stage=stage,
            operation=operation,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            prompt_version=prompt_version,
        )

    def record_retrieval_results(self, count: int) -> None:
        self._delegate.record_retrieval_results(count)

    def record_agent_steps(
        self,
        count: int,
        *,
        outcome: TelemetryOutcome,
        terminal_reason: str | None,
    ) -> None:
        self._delegate.record_agent_steps(
            count,
            outcome=outcome,
            terminal_reason=terminal_reason,
        )

    def record_tool_call(
        self,
        *,
        tool_name: str,
        tool_version: str,
        outcome: TelemetryOutcome,
    ) -> None:
        self._delegate.record_tool_call(
            tool_name=tool_name,
            tool_version=tool_version,
            outcome=outcome,
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
        runtime_configuration: RuntimeConfigurationHashes | None = None,
    ) -> None:
        self._delegate.emit_event(
            event_name,
            attributes,
            duration_ms=duration_ms,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            result_count=result_count,
            step_count=step_count,
            tool_call_count=tool_call_count,
            runtime_configuration=runtime_configuration,
        )

    def record_runtime_configuration(
        self,
        configuration: RuntimeConfigurationHashes,
    ) -> None:
        self._delegate.record_runtime_configuration(configuration)

    def record_ai_operation(self, observation: AIOperationsObservation) -> None:
        self._delegate.record_ai_operation(observation)

    def force_flush(self) -> bool:
        return self._queue.force_flush() and self._delegate.force_flush()

    def shutdown(self) -> bool:
        with self._lock:
            if self._shutdown:
                return False
            self._shutdown = True
        return self._queue.shutdown() and self._delegate.shutdown()


@dataclass(frozen=True, slots=True)
class ExportingTelemetryComposition:
    runtime: ExportingTelemetryRuntime
    local: InMemoryTelemetryComposition
    export_queue: BoundedExportQueue


def build_exporting_telemetry(
    *,
    settings: Settings,
    sink: ExportSink,
) -> ExportingTelemetryComposition:
    """Build the approved injected export path without contacting any endpoint."""

    if settings.telemetry_exporter != "otlp_grpc":
        raise ValueError("exporting telemetry requires the otlp_grpc mode")
    queue = BoundedExportQueue(sink)
    local = build_in_memory_telemetry(settings=settings, export_sink=queue)
    queue.bind_callbacks(
        on_drop=local.runtime.record_export_drop,
        on_failure=local.runtime.record_export_failure,
    )
    queue.start()
    return ExportingTelemetryComposition(
        runtime=ExportingTelemetryRuntime(local.runtime, queue),
        local=local,
        export_queue=queue,
    )


def is_export_failure(record: SafeLogRecord) -> bool:
    return record.event_name is TelemetryEventName.EXPORT_FAILURE
