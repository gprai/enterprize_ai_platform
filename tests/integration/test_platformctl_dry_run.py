"""Integration tests for the offline CLI-to-contract flow."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tools.platformctl.cli import main

from tests.fakes.aws_inventory import (
    FakeApprovalUsageRegistry,
    FakeAwsInventoryProvider,
)

ARTIFACT_SHA256 = "a" * 64
APPROVAL_ID = "approval-w1-004-integration"


class FrozenClock:
    """Deterministic integration clock."""

    def now(self) -> datetime:
        return datetime(2026, 1, 1, 0, 10, tzinfo=UTC)


def write_deploy_approval(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "approval_id": APPROVAL_ID,
                "action": "DEPLOY",
                "environment": "sandbox",
                "aws_account_id": "123456789012",
                "aws_region": "ap-southeast-1",
                "target": "platform",
                "artifact_sha256": ARTIFACT_SHA256,
                "approver": "Gyan-Prakash-Rai",
                "approved_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-01T00:30:00Z",
            }
        ),
        encoding="utf-8",
    )


def deploy_arguments(approval_path: Path) -> list[str]:
    return [
        "deploy",
        "--environment",
        "sandbox",
        "--aws-account-id",
        "123456789012",
        "--aws-region",
        "ap-southeast-1",
        "--target",
        "platform",
        "--artifact-sha256",
        ARTIFACT_SHA256,
        "--approval-record",
        str(approval_path),
        "--confirmation",
        f"CONFIRM DEPLOY sandbox platform {ARTIFACT_SHA256} {APPROVAL_ID}",
        "--executor",
        "Gyan-Prakash-Rai",
        "--resource-expires-at",
        "2026-01-01T12:00:00Z",
    ]


def test_injected_approval_state_allows_offline_deploy_validation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    approval_path = tmp_path / "approval.json"
    write_deploy_approval(approval_path)
    result = main(
        deploy_arguments(approval_path),
        clock=FrozenClock(),
        usage_registry=FakeApprovalUsageRegistry(),
    )
    assert result == 0
    assert capsys.readouterr().out.startswith("DRY_RUN:")


def test_default_approval_state_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    approval_path = tmp_path / "approval.json"
    write_deploy_approval(approval_path)
    result = main(deploy_arguments(approval_path), clock=FrozenClock())
    assert result == 4
    assert "reuse state is unavailable" in capsys.readouterr().err


def test_plan_is_offline_and_does_not_require_approval(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = main(["plan", "--environment", "sandbox", "--target", "platform"])
    assert result == 0
    assert "Terraform plan was NOT RUN" in capsys.readouterr().out


def test_default_cleanliness_inventory_is_indeterminate(
    capsys: pytest.CaptureFixture[str],
) -> None:
    result = main(["verify-clean", "--environment", "sandbox"], clock=FrozenClock())
    assert result == 3
    assert "INDETERMINATE" in capsys.readouterr().err


def test_approved_clean_fake_returns_zero(capsys: pytest.CaptureFixture[str]) -> None:
    result = main(
        ["verify-clean", "--environment", "sandbox"],
        clock=FrozenClock(),
        inventory_provider=FakeAwsInventoryProvider(),
    )
    assert result == 0
    assert "CLEANLINESS PASS" in capsys.readouterr().out
