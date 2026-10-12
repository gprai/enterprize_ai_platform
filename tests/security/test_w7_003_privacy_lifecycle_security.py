"""Security and privacy assertions for W7-003."""

import json

import pytest

from enterprise_ai_platform.ingestion.privacy_lifecycle import (
    LifecycleCoordinator,
    PrivacyLifecycleError,
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


@pytest.mark.asyncio
async def test_cross_tenant_and_replayed_approval_are_rejected() -> None:
    value = plan()
    store = InMemoryApprovalStore()
    coordinator = LifecycleCoordinator(
        vector_store=RecordingVectorStore(),
        object_store=RecordingObjectStore(),
        evidence_archive=RecordingEvidenceArchive(),
        kms=FakeKmsBoundary(),
        approval_store=store,
    )
    wrong_tenant = AuthContext(
        subject_id="admin",
        tenant_id="tenant-b",
        roles=frozenset({Role.ADMIN}),
        clearance=Classification.INTERNAL,
    )
    with pytest.raises(PrivacyLifecycleError, match="DELETION_NOT_AUTHORIZED"):
        await coordinator.delete(value, approval(value), wrong_tenant, now=FIXED_NOW)


def test_plan_and_approval_serialize_no_source_content_or_credentials() -> None:
    value = plan()
    serialized = json.dumps(
        {"plan": value.model_dump(mode="json"), "approval": approval(value).model_dump(mode="json")}
    ).casefold()
    assert "source content" not in serialized
    assert "secret" not in serialized
    assert "access_key" not in serialized
    assert "token" not in serialized
