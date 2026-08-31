"""Security tests for fail-closed W1-004 authorization boundaries."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tools.platformctl.cli import build_parser, main
from tools.platformctl.contracts import ApprovalError, ApprovalRecord

from tests.fakes.aws_inventory import FakeApprovalUsageRegistry

ARTIFACT_SHA256 = "b" * 64


class FrozenClock:
    def now(self) -> datetime:
        return datetime(2026, 1, 1, 0, 10, tzinfo=UTC)


def approval_data() -> dict[str, str]:
    return {
        "schema_version": "1.0",
        "approval_id": "approval-security-001",
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


def test_approval_record_rejects_secret_bearing_contract_drift() -> None:
    data: dict[str, object] = approval_data()
    data["access_token"] = "synthetic-secret"
    with pytest.raises(ApprovalError, match="unknown fields"):
        ApprovalRecord.from_mapping(data)


def test_confirmation_value_is_never_echoed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps(approval_data()), encoding="utf-8")
    synthetic_confirmation = "synthetic-sensitive-confirmation"
    result = main(
        [
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
            synthetic_confirmation,
            "--executor",
            "Gyan-Prakash-Rai",
            "--resource-expires-at",
            "2026-01-01T12:00:00Z",
        ],
        clock=FrozenClock(),
        usage_registry=FakeApprovalUsageRegistry(),
    )
    assert result == 4
    output = capsys.readouterr()
    assert synthetic_confirmation not in output.out
    assert synthetic_confirmation not in output.err


@pytest.mark.parametrize("placeholder", ["TODO", "TODO_USER", "CHANGEME", "PLACEHOLDER"])
def test_runtime_placeholders_are_cli_usage_errors(placeholder: str) -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["plan", "--environment", "sandbox", "--target", placeholder])
    assert exc_info.value.code == 2


def test_uppercase_or_short_artifact_hash_is_cli_usage_error() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            [
                "rollback",
                "--environment",
                "sandbox",
                "--aws-account-id",
                "123456789012",
                "--aws-region",
                "ap-southeast-1",
                "--target",
                "platform",
                "--artifact-sha256",
                "ABC123",
                "--approval-record",
                "approval.json",
                "--confirmation",
                "synthetic",
                "--executor",
                "Gyan-Prakash-Rai",
            ]
        )
    assert exc_info.value.code == 2
