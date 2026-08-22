"""Deterministic W1-004 approval and AWS inventory fakes."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from tools.platformctl.aws_inventory import (
    InventoryResource,
    InventoryUnavailable,
    ServiceIdentifier,
)
from tools.platformctl.contracts import ApprovalStateUnavailable


@dataclass
class FakeApprovalUsageRegistry:
    """Owner-test fake for unused, reused, and unavailable approval state."""

    used_ids: set[str] = field(default_factory=set)
    unavailable: bool = False

    def is_used(self, approval_id: str) -> bool:
        if self.unavailable:
            raise ApprovalStateUnavailable("synthetic approval state is unavailable")
        return approval_id in self.used_ids


@dataclass
class FakeAwsInventoryProvider:
    """Repeatable tag and native-service inventory without AWS access."""

    tagged_resources: Sequence[InventoryResource] = ()
    service_resources: Mapping[ServiceIdentifier, Sequence[InventoryResource]] = field(
        default_factory=dict
    )
    unavailable: bool = False
    tagged_call_count: int = 0
    service_calls: list[ServiceIdentifier] = field(default_factory=list)

    def list_tagged_resources(
        self, required_tags: Mapping[str, str]
    ) -> Sequence[InventoryResource]:
        del required_tags
        self.tagged_call_count += 1
        if self.unavailable:
            raise InventoryUnavailable("synthetic inventory is unavailable")
        return self.tagged_resources

    def list_service_resources(
        self, service: ServiceIdentifier
    ) -> Sequence[InventoryResource]:
        self.service_calls.append(service)
        if self.unavailable:
            raise InventoryUnavailable("synthetic inventory is unavailable")
        return self.service_resources.get(service, ())

