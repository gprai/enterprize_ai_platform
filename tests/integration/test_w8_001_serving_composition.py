from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.serving.fake import FakeInferenceProvider
from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
    ServingProvider,
    ServingRequest,
)


@pytest.mark.integration
def test_offline_fake_composition_preserves_artifact_identity() -> None:
    identity = ArtifactIdentity(
        model_class=ModelClass.FOUNDATION,
        artifact_name="model",
        artifact_version="1",
        artifact_digest="c" * 64,
        source_uri="approved://model/1",
        license="Apache-2.0",
        approval_state=ArtifactApprovalState.APPROVED,
        approval_reference="approval-1",
        tenant_scope="tenant-a",
        classification="INTERNAL",
        processing_region="ap-southeast-1",
        training_identity_reference="train-1",
        inference_identity_reference="infer-1",
    )
    request = ServingRequest(
        request_id="request-1",
        artifact=identity,
        tenant_id="tenant-a",
        classification="INTERNAL",
        authorized=True,
        payload={"prompt": "synthetic"},
    )
    response = asyncio.run(FakeInferenceProvider(ServingProvider.BEDROCK).infer(request))
    assert response.artifact_digest == identity.artifact_digest
