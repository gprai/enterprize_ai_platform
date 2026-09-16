"""Security tests for fail-closed W1-004 authorization boundaries."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from tools.platformctl.cli import build_parser, main
from tools.platformctl.contracts import (
    ApprovalError,
    ApprovalRecord,
    authorize_mutation,
    validate_review_package,
)

from tests.fakes.aws_inventory import FakeApprovalUsageRegistry
from tests.fakes.platform_lifecycle import FrozenClock as ReviewClock
from tests.fakes.platform_lifecycle import reviewed_package_fixture


def test_v2_complete_gate_requires_real_bound_records() -> None:
    package, approval, reader, revalidator = reviewed_package_fixture()
    context = authorize_mutation(
        package, approval, reader=reader, revalidator=revalidator, clock=ReviewClock()
    )
    assert context.package == package
    assert revalidator.calls == 1


@pytest.mark.parametrize(
    "change",
    [
        {"cycle": "W5-CYCLE-B"},
        {"cleanup_owner": "another-owner"},
        {"retention_deadline": "2026-09-15T12:00:00Z"},
        {"operating_seconds": 14401},
        {"deployment_seconds": 7201},
        {"teardown_start_seconds": 10801},
        {"s3_objects": 11},
        {"s3_total_version_bytes": 104857601},
        {"ecr_requests": 65},
        {"log_ingestion_bytes": 104857601},
        {"endpoint_processing_bytes": 1073741825},
        {"destruction_authorized": True},
        {"load_generation": True},
        {"s3_overwrites_or_multipart": True},
    ],
)
def test_prerequisite_terms_are_exact_and_cycle_bound(change):
    from tools.platformctl.contracts import ContractError, validate_prerequisite_terms
    from tools.platformctl.lifecycle_models import PrerequisiteTerms

    now = datetime(2026, 9, 13, 10, tzinfo=UTC)
    validate_prerequisite_terms(PrerequisiteTerms(), now)
    with pytest.raises(ContractError, match="TERMS_CHANGED"):
        validate_prerequisite_terms(replace(PrerequisiteTerms(), **change), now)


def test_prerequisite_clock_never_resets_or_extends_retention():
    from tools.platformctl.contracts import ContractError, validate_prerequisite_terms
    from tools.platformctl.lifecycle_models import PrerequisiteTerms

    terms = PrerequisiteTerms()
    with pytest.raises(ContractError, match="OUTSIDE_RETENTION"):
        validate_prerequisite_terms(
            terms,
            datetime(2026, 9, 15, 1, 15, tzinfo=UTC),
            prepared_at="2026-09-15T01:15:00Z",
        )
    with pytest.raises(ContractError, match="MILESTONE"):
        validate_prerequisite_terms(
            terms,
            datetime(2026, 9, 13, 12, tzinfo=UTC),
            prepared_at="2026-09-13T10:00:00Z",
            deployment=True,
        )
    with pytest.raises(ContractError, match="EXPIRY_CHANGED"):
        validate_prerequisite_terms(
            terms,
            datetime(2026, 9, 13, 10, tzinfo=UTC),
            prepared_at="2026-09-13T10:00:00Z",
            resource_expires_at="2026-09-14T10:00:00Z",
        )
    validate_prerequisite_terms(
        terms,
        datetime(2026, 9, 13, 10, tzinfo=UTC),
        prepared_at="2026-09-13T10:00:00Z",
        resource_expires_at="2026-09-14T09:45:00Z",
    )


def test_current_recovery_requires_retention_and_fresh_prerequisites():
    from tools.platformctl.contracts import ContractError, validate_cycle_prerequisites
    from tools.platformctl.lifecycle_models import ChangeProfile

    package, _, reader, _ = reviewed_package_fixture()
    profile = replace(package.profile, profile=ChangeProfile.PARTIAL_RECOVERY)
    with pytest.raises(ContractError, match="PREREQUISITE_EVIDENCE_REQUIRED"):
        validate_cycle_prerequisites(
            profile,
            package.state,
            reader,
            datetime(2026, 9, 13, 10, tzinfo=UTC),
            prepared_at="2026-09-13T10:00:00Z",
        )


def test_v2_source_drift_fails_before_consumption() -> None:
    package, approval, reader, revalidator = reviewed_package_fixture()
    revalidator.observation = replace(
        revalidator.observation, identities=replace(package.identities, working_sha256="b" * 64)
    )
    try:
        authorize_mutation(
            package, approval, reader=reader, revalidator=revalidator, clock=ReviewClock()
        )
    except ValueError:
        pass
    else:
        raise AssertionError("source drift was accepted")
    assert not revalidator.consumed


def test_direct_cost_consumer_rejects_category_totals_without_resource_coverage():
    from decimal import Decimal

    from tools.platformctl.contracts import ContractError
    from tools.platformctl.cost import validate_prerequisite_cost_bound
    from tools.platformctl.lifecycle_io import canonical_json_bytes
    from tools.platformctl.lifecycle_models import CycleCostBoundBasis

    from tests.unit.test_platformctl_cost import charging_fixture

    basis, reader, now = charging_fixture()
    from hashlib import sha256

    from tools.platformctl.lifecycle_models import EvidenceRef

    raw = canonical_json_bytes(basis)
    reader.payloads["charging.json"] = raw
    ref = EvidenceRef(
        "charging",
        "charging.json",
        sha256(raw).hexdigest(),
        len(raw),
        "fixture",
        "2026-09-13T00:00:00Z",
        "2026-09-22T00:00:00Z",
        "fixture",
    )
    bound = CycleCostBoundBasis(
        "w5-004.lifecycle.v2",
        "W5-CYCLE-A",
        "USD",
        (),
        (),
        ref,
        True,
        True,
        "2026-09-13T00:00:00Z",
        ref,
    )
    with pytest.raises(ContractError, match="RESOURCE_COVERAGE_INCOMPLETE"):
        validate_prerequisite_cost_bound(canonical_json_bytes(bound), Decimal("30"), now, reader)


def test_v2_missing_headroom_cannot_be_approved() -> None:
    package, _, reader, revalidator = reviewed_package_fixture()
    package = replace(package, cost=replace(package.cost, incurred_usd=None))
    try:
        validate_review_package(package, now=ReviewClock().now(), reader=reader)
    except ValueError:
        pass
    else:
        raise AssertionError("unknown spending was accepted")
    assert revalidator.calls == 0


ARTIFACT_SHA256 = "b" * 64


class FrozenClock:
    def now(self) -> datetime:
        return datetime(2026, 1, 1, 0, 10, tzinfo=UTC)


def approval_data() -> dict[str, str]:
    return {
        "schema_version": "1.0",
        "approval_id": "approval-security-001",
        "action": "PLATFORM-APPLY",
        "environment": "sandbox",
        "aws_account_id": "526338061652",
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
            "platform-apply",
            "--environment",
            "sandbox",
            "--aws-account-id",
            "526338061652",
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
        build_parser().parse_args(
            ["platform-plan", "--environment", "sandbox", "--target", placeholder]
        )
    assert exc_info.value.code == 2


def test_uppercase_or_short_artifact_hash_is_cli_usage_error() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(
            [
                "infrastructure-rollback",
                "--environment",
                "sandbox",
                "--aws-account-id",
                "526338061652",
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


@pytest.mark.parametrize("missing", ["git", "terraform", "opa", "infracost"])
def test_direct_authorization_requires_the_complete_tool_inventory(missing: str) -> None:
    from dataclasses import replace

    from tools.platformctl.contracts import ContractError, authorize_mutation

    from tests.fakes.platform_lifecycle import FrozenClock as LifecycleClock
    from tests.fakes.platform_lifecycle import reviewed_package_fixture

    package, approval, reader, revalidator = reviewed_package_fixture()
    incomplete = replace(
        package,
        identities=replace(
            package.identities,
            tools=tuple(item for item in package.identities.tools if item[0] != missing),
        ),
    )
    with pytest.raises(ContractError, match="TOOL_INVENTORY_NOT_EXACT"):
        authorize_mutation(
            incomplete,
            approval,
            reader=reader,
            revalidator=revalidator,
            clock=LifecycleClock(),
        )
    assert revalidator.calls == 0
    assert not revalidator.consumed
