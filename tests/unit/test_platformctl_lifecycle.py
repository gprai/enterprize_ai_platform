"""Unit tests for W1-004 owner approval and lifecycle contracts."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest
from tools.platformctl import deploy
from tools.platformctl.contracts import (
    FIXED_TAG_VALUES,
    Action,
    ApprovalError,
    ApprovalRecord,
    ContractError,
    ExitCode,
    MutationRequest,
    canonical_resource_tags,
    validate_resource_expires_at,
)
from tools.platformctl.destroy import DestroyMode
from tools.platformctl.destroy import validate_request as validate_destroy

from tests.fakes.aws_inventory import FakeApprovalUsageRegistry

NOW = datetime(2026, 1, 1, 0, 10, tzinfo=UTC)
ARTIFACT_SHA256 = "a" * 64
APPROVAL_ID = "approval-w1-004-001"


def approval_mapping(action: str = "DEPLOY", environment: str = "sandbox") -> dict[str, str]:
    return {
        "schema_version": "1.0",
        "approval_id": APPROVAL_ID,
        "action": action,
        "environment": environment,
        "aws_account_id": "123456789012",
        "aws_region": "ap-southeast-1",
        "target": "platform",
        "artifact_sha256": ARTIFACT_SHA256,
        "approver": "Gyan-Prakash-Rai",
        "approved_at": "2026-01-01T00:00:00Z",
        "expires_at": "2026-01-01T00:30:00Z",
    }


def request_for(approval: ApprovalRecord, *, confirmation: str | None = None) -> MutationRequest:
    return MutationRequest(
        action=approval.action,
        environment=approval.environment,
        aws_account_id=approval.aws_account_id,
        aws_region=approval.aws_region,
        target=approval.target,
        artifact_sha256=approval.artifact_sha256,
        confirmation=confirmation or approval.confirmation_text(),
        executor="Gyan-Prakash-Rai",
        resource_expires_at="2026-01-01T12:00:00Z",
    )


def test_deploy_contract_accepts_exact_unused_approval() -> None:
    approval = ApprovalRecord.from_mapping(approval_mapping())
    result = deploy.validate_request(
        request_for(approval), approval, FakeApprovalUsageRegistry(), NOW
    )
    assert result.exit_code is ExitCode.SUCCESS
    assert result.message.startswith("DRY_RUN:")


@pytest.mark.parametrize(
    "confirmation",
    [
        f"confirm DEPLOY sandbox platform {ARTIFACT_SHA256} {APPROVAL_ID}",
        f"CONFIRM DEPLOY  sandbox platform {ARTIFACT_SHA256} {APPROVAL_ID}",
        f" CONFIRM DEPLOY sandbox platform {ARTIFACT_SHA256} {APPROVAL_ID}",
        f"CONFIRM DEPLOY sandbox platform {ARTIFACT_SHA256} {APPROVAL_ID} ",
        f"CONFIRM DEPLOY sandbox platform {ARTIFACT_SHA256} {APPROVAL_ID} extra",
        f"CONFIRM DEPLOY sandbox platform {ARTIFACT_SHA256}",
    ],
)
def test_confirmation_variations_fail_closed(confirmation: str) -> None:
    approval = ApprovalRecord.from_mapping(approval_mapping())
    with pytest.raises(ApprovalError, match="exactly match"):
        deploy.validate_request(
            request_for(approval, confirmation=confirmation),
            approval,
            FakeApprovalUsageRegistry(),
            NOW,
        )


def test_reused_approval_fails_closed() -> None:
    approval = ApprovalRecord.from_mapping(approval_mapping())
    registry = FakeApprovalUsageRegistry(used_ids={APPROVAL_ID})
    with pytest.raises(ApprovalError, match="already been used"):
        deploy.validate_request(request_for(approval), approval, registry, NOW)


@pytest.mark.parametrize(
    ("field_name", "different_value"),
    [
        ("environment", "other-sandbox"),
        ("aws_account_id", "999999999999"),
        ("aws_region", "us-east-1"),
        ("target", "other-platform"),
        ("artifact_sha256", "b" * 64),
    ],
)
def test_request_and_approval_mismatches_fail_closed(field_name: str, different_value: str) -> None:
    approval = ApprovalRecord.from_mapping(approval_mapping())
    request = replace(request_for(approval), **{field_name: different_value})
    with pytest.raises(ApprovalError, match=f"{field_name} does not match"):
        deploy.validate_request(request, approval, FakeApprovalUsageRegistry(), NOW)


def test_one_action_cannot_authorize_another() -> None:
    approval = ApprovalRecord.from_mapping(approval_mapping(action="ROLLBACK"))
    request = replace(request_for(approval), action=Action.DEPLOY)
    with pytest.raises(ApprovalError, match="action does not match"):
        deploy.validate_request(request, approval, FakeApprovalUsageRegistry(), NOW)


def test_approval_lifetime_cannot_exceed_sixty_minutes() -> None:
    data = approval_mapping()
    data["expires_at"] = "2026-01-01T01:00:01Z"
    approval = ApprovalRecord.from_mapping(data)
    with pytest.raises(ApprovalError, match="exceeds 60 minutes"):
        approval.validate_at(NOW)


def test_expired_approval_fails_closed() -> None:
    data = approval_mapping()
    data["expires_at"] = "2026-01-01T00:05:00Z"
    approval = ApprovalRecord.from_mapping(data)
    with pytest.raises(ApprovalError, match="expired"):
        approval.validate_at(NOW)


def test_malformed_approval_timestamp_is_approval_failure() -> None:
    data = approval_mapping()
    data["approved_at"] = "2026-01-01"
    with pytest.raises(ApprovalError, match="ISO-8601 UTC"):
        ApprovalRecord.from_mapping(data)


def test_wrong_executor_fails_closed() -> None:
    approval = ApprovalRecord.from_mapping(approval_mapping())
    request = replace(request_for(approval), executor="Different-Executor")
    with pytest.raises(ApprovalError, match="executor"):
        deploy.validate_request(request, approval, FakeApprovalUsageRegistry(), NOW)


def test_unknown_approval_field_is_rejected() -> None:
    data: dict[str, object] = approval_mapping()
    data["token"] = "synthetic-value"
    with pytest.raises(ApprovalError, match="unknown fields"):
        ApprovalRecord.from_mapping(data)


def test_resource_expiry_is_runtime_bounded() -> None:
    expires_at = validate_resource_expires_at(
        "2026-01-02T00:09:00Z",
        approval_time=datetime(2026, 1, 1, tzinfo=UTC),
        deployment_time=NOW,
        creation_time=NOW,
    )
    assert expires_at == datetime(2026, 1, 2, 0, 9, tzinfo=UTC)

    with pytest.raises(ContractError, match="24-hour"):
        validate_resource_expires_at(
            "2026-01-02T00:11:00Z",
            approval_time=datetime(2026, 1, 1, tzinfo=UTC),
            deployment_time=NOW,
            creation_time=NOW,
        )


def test_canonical_tags_have_no_static_expiry_default() -> None:
    assert "ExpiresAt" not in FIXED_TAG_VALUES
    tags = canonical_resource_tags("sandbox", "2026-01-01T12:00:00Z")
    assert tags == {
        "Project": "enterprise-ai-platform",
        "Owner": "Gyan-Prakash-Rai",
        "ManagedBy": "terraform",
        "CostCenter": "Personal-Learning",
        "Feature": "MVP-001",
        "Repository": "enterprise-ai-platform",
        "Environment": "sandbox",
        "ExpiresAt": "2026-01-01T12:00:00Z",
    }


def test_purge_sandbox_fails_for_every_other_environment() -> None:
    approval = ApprovalRecord.from_mapping(
        approval_mapping(action="PURGE-SANDBOX", environment="production")
    )
    request = request_for(approval)
    with pytest.raises(ContractError, match="only for sandbox"):
        validate_destroy(
            DestroyMode.PURGE_SANDBOX,
            request,
            approval,
            FakeApprovalUsageRegistry(),
            NOW,
        )
