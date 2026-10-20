"""Deterministic W11-004 incident-operation fakes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from enterprise_ai_platform.incident_operations import (
    CommandClassification,
    CommandEvidence,
    GameDayEvidence,
    IncidentPolicy,
    RunnerProfileId,
    ScenarioId,
    build_offline_game_day_evidence,
    load_incident_policy,
)

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 20, 8, 0, tzinfo=UTC)


class FakeClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def now(self) -> datetime:
        current = self.value
        self.value += timedelta(milliseconds=100)
        return current


def policy() -> IncidentPolicy:
    return load_incident_policy(
        ROOT / "configs/incidents/incident-operations.yaml", repository_root=ROOT
    )


def evidence(
    *,
    scenario_id: ScenarioId = ScenarioId.CAPACITY,
    runner_profile: RunnerProfileId = RunnerProfileId.POWERSHELL_7,
) -> GameDayEvidence:
    return build_offline_game_day_evidence(
        policy(),
        scenario_id=scenario_id,
        runner_profile=runner_profile,
        run_id=f"test-{scenario_id.value.casefold()}",
        approval_reference="OWNER-TEST-001-W11-004",
        clock=FakeClock(),
    )


def failed_command(value: CommandEvidence) -> CommandEvidence:
    data = value.model_dump(mode="python")
    data.update(exit_code=7, classification=CommandClassification.FAILED)
    return CommandEvidence.model_validate(data)
