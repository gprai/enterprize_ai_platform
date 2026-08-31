"""Unit tests for tag-plus-native cleanup classification."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from tools.platformctl.aws_inventory import (
    InventoryResource,
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
        scheduled_deletion_at="2026-01-08T00:00:00Z",
    )
    result = verify_clean(
        FakeAwsInventoryProvider(service_resources={ServiceIdentifier.KMS: (pending_key,)}),
        "sandbox",
        NOW,
    )
    assert result.exit_code is ExitCode.SUCCESS
    assert "1 evidenced KMS" in result.message


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
        scheduled_deletion_at="2026-01-08T00:00:00Z",
    )
    result = verify_clean(FakeAwsInventoryProvider(tagged_resources=(key,)), "sandbox", NOW)
    assert result.exit_code is ExitCode.VALIDATION_FAILURE


def test_unavailable_inventory_is_indeterminate_exit_three() -> None:
    result = verify_clean(FakeAwsInventoryProvider(unavailable=True), "sandbox", NOW)
    assert result.exit_code is ExitCode.PROVIDER_UNAVAILABLE
    assert result.message.startswith("INDETERMINATE:")
