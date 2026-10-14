"""Exact policy and request contracts for W9-001."""

from enterprise_ai_platform.training import (
    detect_capability,
    load_training_policy,
    render_training_request,
)
from tests.fakes.w9_001_training import FakeTorchRuntime, make_request


def test_policy_preserves_exact_offline_limits_and_owner_bindings() -> None:
    policy = load_training_policy()

    assert policy.feature_ids == ("TRAIN-001", "COST-006")
    assert policy.region == "ap-southeast-1"
    assert policy.execution_scope == "offline_contract_only"
    assert policy.limits.global_active_training_jobs == 1
    assert policy.limits.per_tenant_active_training_jobs == 1
    assert policy.limits.maximum_instance_count == 1
    assert policy.limits.maximum_runtime_seconds == 21600
    assert policy.limits.maximum_volume_gib == 100
    assert policy.limits.maximum_lora_rank == 64
    assert policy.limits.automatic_retry_attempts == 0
    assert policy.live_execution == "NOT_AUTHORIZED"
    assert policy.provisioning == "NOT_RUN"
    assert set(policy.bindings.model_dump().values()) == {"OWNER_BINDING_REQUIRED"}


def test_rendered_provider_request_is_reviewable_but_not_submittable() -> None:
    request = make_request()
    capability = detect_capability(FakeTorchRuntime(), request.resources.accelerator)
    rendered = render_training_request(request, capability)

    assert rendered["submission_status"] == "NOT_AUTHORIZED"
    assert rendered["role_binding"] == "OWNER_BINDING_REQUIRED"
    assert rendered["output_binding"] == "OWNER_BINDING_REQUIRED"
    assert rendered["enable_network_isolation"] is True
