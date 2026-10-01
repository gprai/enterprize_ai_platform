"""Deterministic, network-free export sinks for W6-002 tests."""

from __future__ import annotations

from enterprise_ai_platform.telemetry import SafeLogRecord


class RecordingExportSink:
    def __init__(self) -> None:
        self.batches: list[tuple[SafeLogRecord, ...]] = []
        self.timeouts: list[float] = []
        self.shutdown_calls = 0

    def export(
        self,
        records: tuple[SafeLogRecord, ...],
        *,
        timeout_seconds: float,
    ) -> bool:
        self.batches.append(records)
        self.timeouts.append(timeout_seconds)
        return True

    def shutdown(self) -> bool:
        self.shutdown_calls += 1
        return True


class FailingExportSink(RecordingExportSink):
    def export(
        self,
        records: tuple[SafeLogRecord, ...],
        *,
        timeout_seconds: float,
    ) -> bool:
        super().export(records, timeout_seconds=timeout_seconds)
        return False
