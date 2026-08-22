"""Offline AWS inventory contracts; no live clients or service calls."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol


class ServiceIdentifier(StrEnum):
    """Complete service-specific cleanup boundary from Source of Truth v1.1."""

    EKS = "EKS"
    ELB = "ELB"
    EBS = "EBS"
    ENI = "ENI"
    EIP = "EIP"
    OPENSEARCH = "OpenSearch"
    S3 = "S3"
    ECR = "ECR"
    CLOUDWATCH_LOGS = "CloudWatch Logs"
    SECRETS_MANAGER = "Secrets Manager"
    KMS = "KMS"
    IAM = "IAM"
    LAMBDA = "Lambda"
    GLUE = "Glue"
    STEP_FUNCTIONS = "Step Functions"
    EVENTBRIDGE = "EventBridge"


class ResourceState(StrEnum):
    """States needed by the offline cleanup classifier."""

    ACTIVE = "ACTIVE"
    PENDING_DELETION = "PENDING_DELETION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class InventoryResource:
    """Sanitized resource metadata returned by an approved inventory provider."""

    service: ServiceIdentifier
    resource_id: str
    tags: Mapping[str, str]
    state: ResourceState
    scheduled_deletion_at: str | None = None


class InventoryUnavailable(RuntimeError):
    """Raised when required inventory cannot be proven."""


class AwsInventoryProvider(Protocol):
    """Dependency-injected boundary for tag and native service discovery."""

    def list_tagged_resources(
        self, required_tags: Mapping[str, str]
    ) -> Sequence[InventoryResource]:
        """Return Resource Groups Tagging API-equivalent results."""
        ...

    def list_service_resources(
        self, service: ServiceIdentifier
    ) -> Sequence[InventoryResource]:
        """Return native service-equivalent results for one service."""
        ...


class UnavailableAwsInventoryProvider:
    """Default runtime boundary that refuses to claim live cleanliness."""

    def list_tagged_resources(
        self, required_tags: Mapping[str, str]
    ) -> Sequence[InventoryResource]:
        """Fail because W1-004 has no approved live adapter."""
        del required_tags
        raise InventoryUnavailable("AWS inventory provider is unavailable")

    def list_service_resources(
        self, service: ServiceIdentifier
    ) -> Sequence[InventoryResource]:
        """Fail because W1-004 has no approved native service adapter."""
        del service
        raise InventoryUnavailable("AWS inventory provider is unavailable")
