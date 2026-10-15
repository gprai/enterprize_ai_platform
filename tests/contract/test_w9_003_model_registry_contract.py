"""Exact policy and provider-rendering contracts for W9-003."""

from enterprise_ai_platform.model_registry import (
    load_registry_policy,
    render_register_model_package_request,
    render_update_model_package_request,
)
from enterprise_ai_platform.retrieval.models import Role
from tests.fakes.w9_003_model_registry import (
    NOW,
    make_auth,
    make_package,
    make_package_approval,
    make_service,
)


def test_policy_preserves_exact_offline_limits_and_stage_order() -> None:
    policy = load_registry_policy()

    assert policy.feature_ids == ("REGISTRY-001",)
    assert policy.region == "ap-southeast-1"
    assert policy.operating_mode == "process_local_memory"
    assert policy.limits.global_active_mutations == 1
    assert policy.limits.per_tenant_active_mutations == 1
    assert policy.limits.maximum_retained_packages == 100
    assert policy.limits.maximum_audit_events == 1000
    assert policy.limits.maximum_request_seconds == 900
    assert policy.limits.automatic_retry_attempts == 0
    assert policy.promotion.stages == ("CANDIDATE", "STAGING", "PRODUCTION")
    assert policy.retention.audit_export_days == 180
    assert policy.network_access is False
    assert policy.approvals.live_registry_mutation == "NOT_AUTHORIZED"
    assert policy.approvals.deployment_approval == "NOT_AUTHORIZED"
    assert policy.bindings.model_package_group_name == "OWNER_BINDING_REQUIRED"


def test_sagemaker_requests_are_exactly_bound_but_never_submitted() -> None:
    admin = make_auth()
    reviewer = make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    service, _ = make_service()
    record = service.register(make_package(auth=admin), admin, now=NOW)
    registration = render_register_model_package_request(record, load_registry_policy())

    assert registration["model_package_group_name"] == "OWNER_BINDING_REQUIRED"
    assert registration["model_approval_status"] == "PendingManualApproval"
    assert registration["submission_status"] == "NOT_AUTHORIZED"
    assert registration["deployment_approval"] == "NOT_AUTHORIZED"

    reviewed = service.review(
        record.package.package_id,
        make_package_approval(record, reviewer=reviewer),
        reviewer,
        now=NOW,
    )
    approval = render_update_model_package_request(reviewed)
    assert approval["model_approval_status"] == "Approved"
    assert approval["submission_status"] == "NOT_AUTHORIZED"
    assert approval["deployment_approval"] == "NOT_AUTHORIZED"
