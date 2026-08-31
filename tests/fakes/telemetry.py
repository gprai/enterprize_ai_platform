"""Deterministic, local-only telemetry collaborators for W4-003 tests."""

from __future__ import annotations

from collections.abc import Sequence

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

PROMPT_SECRET = "PROMPT_SECRET_W4_003"  # noqa: S105
ANSWER_PII = "ANSWER_PII_W4_003"
EVIDENCE_TOKEN = "EVIDENCE_TOKEN_W4_003"  # noqa: S105
TOOL_ARGUMENT = "TOOL_ARGUMENT_W4_003"
CREDENTIAL = "CREDENTIAL_W4_003"  # noqa: S105
EXCEPTION_DETAIL = "EXCEPTION_DETAIL_W4_003"

SECURITY_SENTINELS = (
    PROMPT_SECRET,
    ANSWER_PII,
    EVIDENCE_TOKEN,
    TOOL_ARGUMENT,
    CREDENTIAL,
    EXCEPTION_DETAIL,
)


class DeterministicClock:
    """Advance by a fixed duration without consulting wall-clock state."""

    def __init__(self, *, step_seconds: float = 0.001) -> None:
        self._seconds = 10.0
        self._step_seconds = step_seconds
        self._unix_nanoseconds = 1_800_000_000_000_000_000

    def monotonic(self) -> float:
        value = self._seconds
        self._seconds += self._step_seconds
        return value

    def unix_time_ns(self) -> int:
        value = self._unix_nanoseconds
        self._unix_nanoseconds += int(self._step_seconds * 1_000_000_000)
        return value


class FailingSpanExporter(SpanExporter):
    """Raise one synthetic detail that must never enter captured telemetry."""

    def __init__(self) -> None:
        self.export_calls = 0
        self.flush_calls = 0
        self.shutdown_calls = 0

    def export(self, spans: Sequence[ReadableSpan]) -> SpanExportResult:
        del spans
        self.export_calls += 1
        raise RuntimeError(EXCEPTION_DETAIL)

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        del timeout_millis
        self.flush_calls += 1
        raise RuntimeError(EXCEPTION_DETAIL)

    def shutdown(self) -> None:
        self.shutdown_calls += 1
        raise RuntimeError(EXCEPTION_DETAIL)
