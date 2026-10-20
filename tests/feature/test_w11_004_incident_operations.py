from __future__ import annotations

from enterprise_ai_platform.incident_operations import IncidentStatus, ScenarioId
from tests.fakes.w11_004_incident_operations import evidence, policy


def test_feature_contract_maps_every_w11_004_requirement() -> None:
    value = policy()
    assert value.feature_ids == ("INC-001", "RUNNER-001")
    assert len(value.runner_profiles) == 2
    assert all(command.argv for command in value.commands)
    assert value.execution_bounds.progress_interval_seconds == 5
    assert value.execution_bounds.scenario_deadline_seconds == 900
    assert tuple(item.scenario_id for item in value.scenarios) == tuple(ScenarioId)
    assert value.cleanup_policy.require_native_absence
    assert value.cleanup_policy.require_zero_unexpected_residue
    assert value.corrective_action_policy.block_pass_when_incomplete
    assert value.evidence_policy.preserve_failed_evidence


def test_recovery_evidence_has_roadmap_fields() -> None:
    value = evidence(scenario_id=ScenarioId.DEPENDENCY_FAILURE)
    assert value.status is IncidentStatus.PASS
    assert value.source_identities
    assert value.recovered_identities
    assert value.approval_references
    assert value.command_evidence
    assert value.target_rto_seconds == 28800
    assert value.target_rpo_seconds == 86400
    assert value.integrity_ok and value.health_ok
    assert value.cleanup_complete
    assert not value.failed_steps
    assert not value.skipped_steps
    assert value.residual_risk
    assert value.review_completed
    assert value.review_summary
