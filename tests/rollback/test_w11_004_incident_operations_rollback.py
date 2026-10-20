from __future__ import annotations

from tests.fakes.w11_004_incident_operations import evidence, policy

from enterprise_ai_platform.incident_operations import RunbookStage, ScenarioId


def test_dependency_failure_returns_to_approved_rollback_stage() -> None:
    value = policy()
    scenario = next(
        item for item in value.scenarios if item.scenario_id is ScenarioId.DEPENDENCY_FAILURE
    )
    assert scenario.required_terminal_action is RunbookStage.ROLLBACK
    assert value.runbook.last_validated_identity.startswith("sha256:")


def test_failed_evidence_contract_is_retained() -> None:
    value = evidence(scenario_id=ScenarioId.DEPENDENCY_FAILURE)
    assert value.evidence_retained
    assert value.runbook_identity == policy().runbook.last_validated_identity
    assert value.terminal_action is RunbookStage.ROLLBACK
