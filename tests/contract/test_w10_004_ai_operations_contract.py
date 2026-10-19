"""Contract checks for W10-004 schemas, metrics, and policy."""

from enterprise_ai_platform.telemetry.ai_operations import (
    AI_OPERATIONS_METRIC_NAMES,
    AI_OPERATIONS_POLICY_SCHEMA_VERSION,
    AI_OPERATIONS_SCHEMA_VERSION,
    AIOperationsObservation,
    AIOperationsSignal,
    load_ai_operations_policy,
)


def test_policy_and_observation_schema_are_versioned_and_default_off() -> None:
    policy = load_ai_operations_policy()
    observation = AIOperationsObservation(
        signal=AIOperationsSignal.RETRIEVAL_QUALITY,
        value=1.0,
        outcome="success",
    )
    assert policy.schema_version == AI_OPERATIONS_POLICY_SCHEMA_VERSION
    assert observation.schema_version == AI_OPERATIONS_SCHEMA_VERSION
    assert policy.enabled_by_default is False
    assert policy.privacy.raw_prompt_capture is False
    assert policy.privacy.raw_response_capture is False
    assert policy.privacy.encryption_in_transit_required is True
    assert policy.privacy.access_control == "existing_observability_rbac"


def test_ai_metric_inventory_extends_the_existing_namespace() -> None:
    ai_names = set(AI_OPERATIONS_METRIC_NAMES.values())
    assert len(ai_names) == 10
    assert all(name.startswith("enterprise_ai.ai.") for name in ai_names)
    assert "enterprise_ai.ai.request.cost_usd" in ai_names
    assert "enterprise_ai.ai.configuration.drift" in ai_names
