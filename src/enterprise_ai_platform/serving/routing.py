"""Deterministic, offline serving-route selection and authorization checks."""

from __future__ import annotations

from pydantic import Field

from enterprise_ai_platform.serving.errors import (
    ServingArtifactApprovalError,
    ServingAuthorizationError,
)
from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
    ServingModel,
    ServingProvider,
    ServingRequest,
)


class RoutingEvidence(ServingModel):
    platform_control_required: bool = False
    gpu_or_multimodel_required: bool = False
    latency_requirement_ms: int | None = Field(default=None, gt=0, le=120_000)
    eks_approval_reference: str | None = Field(default=None, min_length=1, max_length=200)
    structured_ml_admission_reference: str | None = Field(
        default=None,
        min_length=1,
        max_length=200,
    )


def validate_request_authorization(request: ServingRequest) -> None:
    if not request.authorized:
        raise ServingAuthorizationError
    if request.tenant_id != request.artifact.tenant_scope:
        raise ServingAuthorizationError
    if request.classification != request.artifact.classification:
        raise ServingAuthorizationError


def route_artifact(
    artifact: ArtifactIdentity,
    evidence: RoutingEvidence | None = None,
) -> ServingProvider:
    evidence = evidence or RoutingEvidence()
    if artifact.approval_state is not ArtifactApprovalState.APPROVED:
        raise ServingArtifactApprovalError
    if artifact.model_class is ModelClass.FOUNDATION:
        return ServingProvider.BEDROCK
    if (
        artifact.model_class is ModelClass.STRUCTURED
        and evidence.structured_ml_admission_reference is None
    ):
        raise ServingArtifactApprovalError
    if (
        evidence.platform_control_required
        or evidence.gpu_or_multimodel_required
        or evidence.latency_requirement_ms is not None
    ):
        if evidence.eks_approval_reference is None:
            raise ServingArtifactApprovalError
        return ServingProvider.EKS
    return ServingProvider.SAGEMAKER_REALTIME
