"""Deterministic local fakes for W7-003 privacy and lifecycle tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from enterprise_ai_platform.ingestion.governance import canonical_sha256
from enterprise_ai_platform.ingestion.models import PiiPolicy, load_pii_policy
from enterprise_ai_platform.ingestion.privacy_lifecycle import (
    DestructiveApproval,
    EvidenceArchiveReceipt,
    EvidenceState,
    LifecycleOperation,
    LifecyclePlan,
    MacieDiscovery,
    RetainedResource,
    RetainedResourceKind,
    SourceObjectVersion,
    load_privacy_lifecycle_config,
)
from enterprise_ai_platform.retrieval.models import CollectionSpec

FIXED_NOW = datetime(2026, 10, 12, 6, 0, tzinfo=UTC)
KMS_ARN = "arn:aws:kms:ap-southeast-1:526338061652:key/shared-platform-key"


def config():
    from pathlib import Path

    return load_privacy_lifecycle_config(Path("configs/ingestion/w7-003.yaml"))


def pii_policy() -> PiiPolicy:
    from pathlib import Path

    return load_pii_policy(Path("configs/pii-policy.yaml"))


def source() -> SourceObjectVersion:
    return SourceObjectVersion(
        bucket="enterprise-ai-platform-526338061652-ap-southeast-1-sandbox",
        key="raw/tenant-a/document-1.txt",
        version_id="version-1",
        tenant_id="tenant-a",
        document_id="document-1",
        document_version="v1",
        content_sha256="a" * 64,
    )


def discovery(
    source_identity: str,
    *,
    state: EvidenceState = EvidenceState.PASSED,
    classification: str | None = "INTERNAL",
) -> MacieDiscovery:
    payload = {"source": source_identity, "state": state.value}
    return MacieDiscovery(
        source_identity_sha256=source_identity,
        state=state,
        classification=classification,
        finding_types=(),
        result_identity_sha256=canonical_sha256(payload),
    )


def plan() -> LifecyclePlan:
    target = source()
    return LifecyclePlan(
        schema_version="w7-003.lifecycle-plan.v1",
        operation=LifecycleOperation.DELETE,
        tenant_id="tenant-a",
        source=target,
        index_manifest_sha256="b" * 64,
        evidence_payload_sha256="c" * 64,
        collection=CollectionSpec(name="w7_003_test"),
        retained_resources=(
            RetainedResource(
                kind=RetainedResourceKind.SHARED_BUCKET,
                resource_identity=target.bucket,
                retained_reason="shared platform data-zone bucket",
            ),
            RetainedResource(
                kind=RetainedResourceKind.SHARED_INDEX,
                resource_identity="w7_003_test",
                retained_reason="shared retrieval collection",
            ),
            RetainedResource(
                kind=RetainedResourceKind.SHARED_KMS_KEY,
                resource_identity=KMS_ARN,
                retained_reason="shared evidence encryption key",
            ),
            RetainedResource(
                kind=RetainedResourceKind.SERVICE_LINKED_ROLE,
                resource_identity="AWSServiceRoleForAmazonMacie",
                retained_reason="service-linked resource",
            ),
        ),
        created_at=FIXED_NOW,
        destruction_eligible_at=FIXED_NOW,
    )


def approval(value: LifecyclePlan) -> DestructiveApproval:
    return DestructiveApproval(
        approval_id="owner-approval-1",
        operation=value.operation,
        owner="Gyan Prakash Rai",
        tenant_id=value.tenant_id,
        plan_identity_sha256=value.identity,
        target_identity_sha256=value.source.identity,
        issued_at=FIXED_NOW,
        expires_at=FIXED_NOW + timedelta(minutes=15),
        one_time_use=True,
    )


class FakeMacieBoundary:
    def __init__(self, result: MacieDiscovery) -> None:
        self.result = result
        self.calls = 0

    async def discover(self, source: SourceObjectVersion) -> MacieDiscovery:
        del source
        self.calls += 1
        return self.result


class InMemoryApprovalStore:
    def __init__(self) -> None:
        self.used: set[str] = set()

    def consume(self, approval: DestructiveApproval, *, now: datetime) -> bool:
        del now
        if approval.approval_id in self.used:
            return False
        self.used.add(approval.approval_id)
        return True


class RecordingVectorStore:
    def __init__(self, count: int = 1, *, retain_after_delete: bool = False) -> None:
        self.count = count
        self.retain_after_delete = retain_after_delete
        self.calls: list[str] = []

    async def count_by_document_version(self, *args, **kwargs) -> int:
        del args, kwargs
        self.calls.append("count")
        return self.count

    async def delete_by_document_version(self, *args, **kwargs) -> None:
        del args, kwargs
        self.calls.append("delete")
        if not self.retain_after_delete:
            self.count = 0


class RecordingObjectStore:
    def __init__(self, *, retain_after_delete: bool = False) -> None:
        self.exists = True
        self.retain_after_delete = retain_after_delete
        self.calls: list[str] = []

    async def delete_exact_version(self, source: SourceObjectVersion) -> None:
        del source
        self.calls.append("delete")
        if not self.retain_after_delete:
            self.exists = False

    async def exact_version_exists(self, source: SourceObjectVersion) -> bool:
        del source
        self.calls.append("exists")
        return self.exists


class RecordingEvidenceArchive:
    def __init__(self, *, usable_key: str = KMS_ARN) -> None:
        self.usable_key = usable_key
        self.calls = 0

    async def archive_redacted_metadata(self, value: LifecyclePlan) -> EvidenceArchiveReceipt:
        self.calls += 1
        return EvidenceArchiveReceipt(
            evidence_identity_sha256="d" * 64,
            source_identity_sha256=value.source.identity,
            payload_sha256=value.evidence_payload_sha256,
            encryption_key_arn=self.usable_key,
            contains_source_content=False,
            archived_at=FIXED_NOW,
        )


class FakeKmsBoundary:
    def __init__(self, usable: bool = True) -> None:
        self.usable = usable
        self.calls: list[str] = []

    async def is_usable(self, key_arn: str) -> bool:
        self.calls.append(key_arn)
        return self.usable
