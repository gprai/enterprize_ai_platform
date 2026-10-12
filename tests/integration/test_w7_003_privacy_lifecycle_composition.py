"""Composition coverage for the W7-003 witnessed deletion chain."""

import pytest

from enterprise_ai_platform.ingestion.privacy_lifecycle import (
    EvidenceState,
    LifecycleCoordinator,
)
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role
from tests.fakes.w7_003_privacy_lifecycle import (
    FIXED_NOW,
    FakeKmsBoundary,
    InMemoryApprovalStore,
    RecordingEvidenceArchive,
    RecordingObjectStore,
    RecordingVectorStore,
    approval,
    plan,
)


def admin() -> AuthContext:
    return AuthContext(
        subject_id="owner-test-admin",
        tenant_id="tenant-a",
        roles=frozenset({Role.ADMIN}),
        clearance=Classification.INTERNAL,
    )


@pytest.mark.asyncio
async def test_exact_deletion_is_archived_indexed_and_absence_verified() -> None:
    value = plan()
    vectors = RecordingVectorStore()
    objects = RecordingObjectStore()
    archive = RecordingEvidenceArchive()
    kms = FakeKmsBoundary()
    coordinator = LifecycleCoordinator(
        vector_store=vectors,
        object_store=objects,
        evidence_archive=archive,
        kms=kms,
        approval_store=InMemoryApprovalStore(),
    )

    receipt = await coordinator.delete(value, approval(value), admin(), now=FIXED_NOW)

    assert receipt.state is EvidenceState.PASSED
    assert vectors.calls == ["count", "delete", "count"]
    assert objects.calls == ["delete", "exists"]
    assert archive.calls == 1
    assert kms.calls


@pytest.mark.asyncio
async def test_index_absence_failure_preserves_source_version() -> None:
    value = plan()
    objects = RecordingObjectStore()
    coordinator = LifecycleCoordinator(
        vector_store=RecordingVectorStore(retain_after_delete=True),
        object_store=objects,
        evidence_archive=RecordingEvidenceArchive(),
        kms=FakeKmsBoundary(),
        approval_store=InMemoryApprovalStore(),
    )

    receipt = await coordinator.delete(value, approval(value), admin(), now=FIXED_NOW)
    assert receipt.state is EvidenceState.INDETERMINATE
    assert receipt.safe_reason_code == "INDEX_ABSENCE_NOT_PROVEN"
    assert objects.calls == []
