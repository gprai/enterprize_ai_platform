from __future__ import annotations

from enterprise_ai_platform.incident_operations import (
    IncidentStatus,
    RunnerProfileId,
    ScenarioId,
    build_offline_game_day_evidence,
)
from tests.fakes.w11_004_incident_operations import FakeClock, policy


def test_each_scenario_produces_identity_bound_local_evidence() -> None:
    value = policy()
    for scenario in ScenarioId:
        result = build_offline_game_day_evidence(
            value,
            scenario_id=scenario,
            runner_profile=RunnerProfileId.POWERSHELL_7,
            run_id=f"integration-{scenario.value.casefold()}",
            approval_reference="OWNER-TEST-001-W11-004",
            clock=FakeClock(),
        )
        assert result.status is IncidentStatus.PASS
        assert result.scope == "LOCAL_FAKE"
        assert result.runner_execution == "SIMULATED_PROFILE_SELECTION"
        assert result.source_identities == result.recovered_identities
        assert all(item.native_verification.identity_match for item in result.command_evidence)
        assert result.residual_risk == (
            "local fake does not establish live or production readiness",
        )


def test_terminal_action_is_bound_to_scenario() -> None:
    value = policy()
    actions = {item.scenario_id: item.required_terminal_action for item in value.scenarios}
    assert actions[ScenarioId.CAPACITY] == "RECOVERY"
    assert actions[ScenarioId.SATURATION] == "RECOVERY"
    assert actions[ScenarioId.DEPENDENCY_FAILURE] == "ROLLBACK"
