"""Deterministic SageMaker-compatible request rendering without submission."""

from __future__ import annotations

from typing import cast

from enterprise_ai_platform.json_contracts import JSONValue

from .models import CapabilityEvidence, TrainingOutcome, TrainingRequest, TrainingResult
from .serialization import fingerprint


def render_training_request(
    request: TrainingRequest, capability: CapabilityEvidence
) -> dict[str, JSONValue]:
    """Render a reviewable request document; this function cannot submit a job."""

    return {
        "algorithm_specification": {
            "training_image": request.container.registry_uri,
            "training_image_digest": request.container.image_digest,
        },
        "approval_reference_sha256": request.approval_reference_sha256,
        "budget_reference_sha256": request.budget_reference_sha256,
        "capability": {
            "accelerator": capability.accelerator.value,
            "device_count": capability.device_count,
            "runtime_version": capability.runtime_version,
        },
        "code_identity": request.code.model_dump(mode="json"),
        "data_identity": request.data.model_dump(mode="json"),
        "enable_inter_container_traffic_encryption": True,
        "enable_network_isolation": True,
        "hyperparameters": {item.key: item.value for item in request.hyperparameters},
        "model_identity": request.model.model_dump(mode="json"),
        "output_binding": "OWNER_BINDING_REQUIRED",
        "resource_config": {
            "instance_count": request.resources.instance_count,
            "instance_type": request.resources.instance_type,
            "volume_gib": request.resources.volume_gib,
        },
        "role_binding": "OWNER_BINDING_REQUIRED",
        "stopping_condition": {"maximum_runtime_seconds": request.resources.runtime_seconds},
        "submission_status": "NOT_AUTHORIZED",
        "tags": {
            "correlation_identity_sha256": fingerprint(request.correlation_id),
            "request_identity_sha256": fingerprint(request),
            "tenant_reference_sha256": request.tenant_reference_sha256,
        },
    }


class OfflineSageMakerProvider:
    """Offline provider that returns only an identity-bound candidate specification."""

    def prepare(self, request: TrainingRequest, capability: CapabilityEvidence) -> TrainingResult:
        rendered = cast(object, render_training_request(request, capability))
        provider_request_sha256 = fingerprint(rendered)
        return TrainingResult(
            request_identity_sha256=fingerprint(request),
            outcome=TrainingOutcome.CANDIDATE_READY,
            provider_request_sha256=provider_request_sha256,
            candidate_artifact_sha256=fingerprint(
                {
                    "kind": "candidate_training_specification",
                    "provider_request_sha256": provider_request_sha256,
                }
            ),
            safe_reason_code="OFFLINE_CANDIDATE_SPEC_READY",
        )
