"""Fail-closed cleanup classification over injected inventory interfaces."""

from __future__ import annotations

from datetime import datetime

from .aws_inventory import (
    AwsInventoryProvider,
    InventoryResource,
    InventoryUnavailable,
    ResourceState,
    ServiceIdentifier,
)
from .contracts import (
    ContractError,
    ExitCode,
    OperationResult,
    parse_utc_timestamp,
    stable_cleanup_tags,
)


def _resource_key(resource: InventoryResource) -> tuple[ServiceIdentifier, str]:
    return resource.service, resource.resource_id


def _has_managed_tags(resource: InventoryResource, required_tags: dict[str, str]) -> bool:
    if not resource.resource_id:
        return False
    if any(resource.tags.get(key) != value for key, value in required_tags.items()):
        return False
    resource_expiry = resource.tags.get("ExpiresAt")
    if resource_expiry is None:
        return False
    try:
        parse_utc_timestamp(resource_expiry, "resource ExpiresAt")
    except ContractError:
        return False
    return True


def _is_expected_kms_residual(resource: InventoryResource, now: datetime) -> bool:
    if resource.service is not ServiceIdentifier.KMS:
        return False
    if resource.state is not ResourceState.PENDING_DELETION:
        return False
    if resource.scheduled_deletion_at is None:
        return False
    try:
        scheduled_at = parse_utc_timestamp(resource.scheduled_deletion_at, "scheduled KMS deletion")
    except ContractError:
        return False
    return scheduled_at > now


def verify_clean(
    provider: AwsInventoryProvider,
    environment: str,
    now: datetime,
) -> OperationResult:
    """Combine tag and native checks without claiming unavailable inventory."""
    required_tags = stable_cleanup_tags(environment)
    resources: dict[tuple[ServiceIdentifier, str], InventoryResource] = {}
    try:
        for resource in provider.list_tagged_resources(required_tags):
            resources[_resource_key(resource)] = resource
        for service in ServiceIdentifier:
            for resource in provider.list_service_resources(service):
                resources[_resource_key(resource)] = resource
    except InventoryUnavailable:
        return OperationResult(
            ExitCode.PROVIDER_UNAVAILABLE,
            "INDETERMINATE: required AWS inventory provider is unavailable",
        )

    unmanaged_count = 0
    active_or_unknown_count = 0
    expected_kms_count = 0
    for resource in resources.values():
        managed = _has_managed_tags(resource, required_tags)
        if not managed:
            unmanaged_count += 1
            continue
        if _is_expected_kms_residual(resource, now):
            expected_kms_count += 1
            continue
        active_or_unknown_count += 1

    if unmanaged_count or active_or_unknown_count:
        return OperationResult(
            ExitCode.VALIDATION_FAILURE,
            "CLEANLINESS FAIL: "
            f"{unmanaged_count} unmanaged and "
            f"{active_or_unknown_count} active/unknown residual(s)",
        )

    return OperationResult(
        ExitCode.SUCCESS,
        "CLEANLINESS PASS: no active or unmanaged residuals; "
        f"{expected_kms_count} evidenced KMS PendingDeletion residual(s)",
    )
