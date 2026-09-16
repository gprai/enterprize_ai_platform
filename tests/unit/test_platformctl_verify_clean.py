"""Unit tests for tag-plus-native cleanup classification."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tools.platformctl.aws_inventory import (
    InventoryResource,
    KmsSchedulingEvidence,
    ResourceState,
    ServiceIdentifier,
)
from tools.platformctl.contracts import ExitCode, canonical_resource_tags
from tools.platformctl.verify_clean import verify_clean

from tests.fakes.aws_inventory import FakeAwsInventoryProvider

NOW = datetime(2026, 1, 1, 0, 10, tzinfo=UTC)


def managed_tags() -> dict[str, str]:
    return canonical_resource_tags("sandbox", "2026-01-01T12:00:00Z")


def test_clean_fake_queries_tags_and_every_native_service() -> None:
    provider = FakeAwsInventoryProvider()
    result = verify_clean(provider, "sandbox", NOW)
    assert result.exit_code is ExitCode.SUCCESS
    assert provider.tagged_call_count == 1
    assert provider.service_calls == list(ServiceIdentifier)


def test_unmanaged_residual_fails() -> None:
    residual = InventoryResource(
        service=ServiceIdentifier.S3,
        resource_id="synthetic-bucket",
        tags={},
        state=ResourceState.ACTIVE,
    )
    result = verify_clean(FakeAwsInventoryProvider(tagged_resources=(residual,)), "sandbox", NOW)
    assert result.exit_code is ExitCode.VALIDATION_FAILURE
    assert "1 unmanaged" in result.message


def test_managed_active_residual_fails() -> None:
    residual = InventoryResource(
        service=ServiceIdentifier.EKS,
        resource_id="synthetic-cluster",
        tags=managed_tags(),
        state=ResourceState.ACTIVE,
    )
    result = verify_clean(
        FakeAwsInventoryProvider(service_resources={ServiceIdentifier.EKS: (residual,)}),
        "sandbox",
        NOW,
    )
    assert result.exit_code is ExitCode.VALIDATION_FAILURE
    assert "1 active/unknown" in result.message


def test_evidenced_kms_pending_deletion_is_the_only_expected_residual() -> None:
    pending_key = InventoryResource(
        service=ServiceIdentifier.KMS,
        resource_id="synthetic-key",
        tags=managed_tags(),
        state=ResourceState.PENDING_DELETION,
        scheduled_deletion_at="2026-01-08T00:10:00Z",
    )
    result = verify_clean(
        FakeAwsInventoryProvider(service_resources={ServiceIdentifier.KMS: (pending_key,)}),
        "sandbox",
        NOW,
        scheduling_evidence=(
            KmsSchedulingEvidence(
                "synthetic-key",
                "526338061652",
                "ap-southeast-1",
                "2026-01-01T00:10:00Z",
                "2026-01-08T00:10:00Z",
                7,
                "owner-deletion",
                "a" * 64,
            ),
        ),
    )
    assert result.exit_code is ExitCode.SUCCESS
    assert "1 evidenced KMS" in result.message


def test_later_kms_verification_uses_original_schedule() -> None:
    from datetime import timedelta

    record = KmsSchedulingEvidence(
        "synthetic-key",
        "526338061652",
        "ap-southeast-1",
        "2026-01-01T00:10:00Z",
        "2026-01-08T00:10:00Z",
        7,
        "owner-deletion",
        "a" * 64,
    )
    key = InventoryResource(
        ServiceIdentifier.KMS,
        "synthetic-key",
        managed_tags(),
        ResourceState.PENDING_DELETION,
        scheduled_deletion_at=record.deletion_at,
    )
    provider = FakeAwsInventoryProvider(service_resources={ServiceIdentifier.KMS: (key,)})
    assert (
        verify_clean(
            provider, "sandbox", NOW + timedelta(days=2), scheduling_evidence=(record,)
        ).exit_code
        is ExitCode.SUCCESS
    )
    assert (
        verify_clean(
            provider, "sandbox", NOW + timedelta(days=8), scheduling_evidence=(record,)
        ).exit_code
        is ExitCode.VALIDATION_FAILURE
    )


def test_insufficient_kms_evidence_fails() -> None:
    pending_key = InventoryResource(
        service=ServiceIdentifier.KMS,
        resource_id="synthetic-key",
        tags=managed_tags(),
        state=ResourceState.PENDING_DELETION,
    )
    result = verify_clean(FakeAwsInventoryProvider(tagged_resources=(pending_key,)), "sandbox", NOW)
    assert result.exit_code is ExitCode.VALIDATION_FAILURE


@pytest.mark.parametrize("state", [ResourceState.ACTIVE, ResourceState.UNKNOWN])
def test_active_or_unknown_kms_state_fails(state: ResourceState) -> None:
    key = InventoryResource(
        service=ServiceIdentifier.KMS,
        resource_id="synthetic-key",
        tags=managed_tags(),
        state=state,
        scheduled_deletion_at="2026-01-08T00:10:00Z",
    )
    result = verify_clean(FakeAwsInventoryProvider(tagged_resources=(key,)), "sandbox", NOW)
    assert result.exit_code is ExitCode.VALIDATION_FAILURE


def test_unavailable_inventory_is_indeterminate_exit_three() -> None:
    result = verify_clean(FakeAwsInventoryProvider(unavailable=True), "sandbox", NOW)
    assert result.exit_code is ExitCode.PROVIDER_UNAVAILABLE
    assert result.message.startswith("INDETERMINATE:")


def test_kms_pending_deletion_outside_exact_seven_day_window_fails() -> None:
    pending_key = InventoryResource(
        service=ServiceIdentifier.KMS,
        resource_id="synthetic-key",
        tags=managed_tags(),
        state=ResourceState.PENDING_DELETION,
        scheduled_deletion_at="2026-01-08T00:11:00Z",
    )
    result = verify_clean(FakeAwsInventoryProvider(tagged_resources=(pending_key,)), "sandbox", NOW)
    assert result.exit_code is ExitCode.VALIDATION_FAILURE


def test_explicit_shared_or_unrelated_resources_are_excluded_not_deleted() -> None:
    shared = InventoryResource(
        service=ServiceIdentifier.IAM,
        resource_id="owner-managed-role",
        tags={},
        state=ResourceState.ACTIVE,
        owner_classification="OWNER_MANAGED",
    )
    unrelated = InventoryResource(
        service=ServiceIdentifier.S3,
        resource_id="unrelated-bucket",
        tags={},
        state=ResourceState.ACTIVE,
        owner_classification="UNRELATED",
    )
    result = verify_clean(
        FakeAwsInventoryProvider(tagged_resources=(shared, unrelated)),
        "sandbox",
        NOW,
    )
    assert result.exit_code is ExitCode.SUCCESS
