from __future__ import annotations

import pytest

from enterprise_ai_platform.serving.errors import ServingAuthorizationError
from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
    ServingRequest,
)
from enterprise_ai_platform.serving.routing import validate_request_authorization


def test_wrong_tenant_fails_before_provider_boundary() -> None:
    identity = ArtifactIdentity(
        model_class=ModelClass.FOUNDATION,
        artifact_name="model",
        artifact_version="1",
        artifact_digest="e" * 64,
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
        tenant_id="tenant-b",
        classification="INTERNAL",
        authorized=True,
        payload={"prompt": "synthetic"},
    )
    with pytest.raises(ServingAuthorizationError):
        validate_request_authorization(request)
