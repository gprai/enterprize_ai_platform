"""Deterministic, content-free W11-002 fault and observation fixtures."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from enterprise_ai_platform.chaos import (
    ChaosPolicy,
    InMemoryFaultTarget,
    InMemoryObserver,
    LocalObservation,
    synthetic_observer,
)

NOW = datetime(2026, 10, 19, 12, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self) -> None:
        self.elapsed = 0.0
        self.is_cancelled = False
        self.utc_now = NOW

    def now_utc(self) -> datetime:
        return self.utc_now

    def monotonic(self) -> float:
        return self.elapsed

    def cancelled(self) -> bool:
        return self.is_cancelled

    def advance(self, seconds: float) -> None:
        self.elapsed += seconds
        self.utc_now += timedelta(seconds=seconds)


class RecordingFault(InMemoryFaultTarget):
    def __init__(self, *, restore_fails: bool = False) -> None:
        super().__init__()
        self.restore_fails = restore_fails
        self.events: list[str] = []

    def inject(self, scenario_id: str) -> None:
        self.events.append("inject")
        super().inject(scenario_id)

    def restore(self) -> None:
        self.events.append("restore")
        if self.restore_fails:
            raise ValueError("synthetic restore failed")
        super().restore()


class RecordingObserver(InMemoryObserver):
    def __init__(self, before: LocalObservation, after: LocalObservation) -> None:
        super().__init__(before, after)
        self.phases: list[str] = []

    def sample(self, phase: str) -> LocalObservation:  # type: ignore[override]
        self.phases.append(phase)
        if phase == "before":
            return self.before
        if phase == "after":
            return self.after
        raise ValueError("unknown synthetic observation phase")


def observations(policy: ChaosPolicy, scenario_id: str) -> RecordingObserver:
    source = synthetic_observer(policy, scenario_id, observed_at=NOW)
    return RecordingObserver(source.before, source.after)


def changed_observation(observation: LocalObservation, **changes: object) -> LocalObservation:
    values = observation.model_dump()
    values.update(changes)
    return LocalObservation.model_validate(values)
