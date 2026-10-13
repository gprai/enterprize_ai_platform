from __future__ import annotations

import pytest

from enterprise_ai_platform.serving.errors import ServingArtifactApprovalError
from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
    ServingProvider,
)
from enterprise_ai_platform.serving.routing import RoutingEvidence, route_artifact


def artifact(model_class: ModelClass = ModelClass.FOUNDATION) -> ArtifactIdentity:
    return ArtifactIdentity(
        model_class=model_class,
        artifact_name="approved-model",
        artifact_version="1",
        artifact_digest="a" * 64,
        source_uri="approved://model/1",
        license="Apache-2.0",
        approval_state=ArtifactApprovalState.APPROVED,
        approval_reference="ADR-019-approval-1",
        tenant_scope="tenant-a",
        classification="INTERNAL",
        processing_region="ap-southeast-1",
        training_identity_reference="training-role-1",
        inference_identity_reference="inference-role-1",
    )


def test_foundation_routes_to_bedrock() -> None:
    assert route_artifact(artifact()) is ServingProvider.BEDROCK


def test_custom_routes_to_sagemaker_by_default() -> None:
    assert route_artifact(artifact(ModelClass.CUSTOM)) is ServingProvider.SAGEMAKER_REALTIME


def test_eks_requires_explicit_approval_reference() -> None:
    with pytest.raises(ServingArtifactApprovalError):
        route_artifact(
            artifact(ModelClass.CUSTOM),
            RoutingEvidence(gpu_or_multimodel_required=True),
        )
