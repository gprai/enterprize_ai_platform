from enterprise_ai_platform.serving.errors import ServingArtifactApprovalError
from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
)
from enterprise_ai_platform.serving.routing import RoutingEvidence, route_artifact


def test_model_classes_have_the_approved_default_routes() -> None:
    def make(model_class: ModelClass) -> ArtifactIdentity:
        return ArtifactIdentity(
            model_class=model_class,
            artifact_name="model",
            artifact_version="1",
            artifact_digest="d" * 64,
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

    assert route_artifact(make(ModelClass.FOUNDATION)).value == "bedrock"
    assert route_artifact(make(ModelClass.CUSTOM)).value == "sagemaker_realtime"

    try:
        route_artifact(make(ModelClass.STRUCTURED))
    except ServingArtifactApprovalError:
        pass
    else:
        raise AssertionError("structured serving requires W7-004 admission")

    assert (
        route_artifact(
            make(ModelClass.STRUCTURED),
            RoutingEvidence(structured_ml_admission_reference="W7-004-admission-1"),
        ).value
        == "sagemaker_realtime"
    )
