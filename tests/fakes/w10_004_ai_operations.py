"""Content-free W10-004 telemetry fake."""

from __future__ import annotations

from enterprise_ai_platform.telemetry.ai_operations import AIOperationsObservation
from enterprise_ai_platform.telemetry.runtime import NullTelemetryRuntime


class RecordingAIOperationsRuntime(NullTelemetryRuntime):
    def __init__(self) -> None:
        self.observations: list[AIOperationsObservation] = []

    def record_ai_operation(self, observation: AIOperationsObservation) -> None:
        self.observations.append(observation)
