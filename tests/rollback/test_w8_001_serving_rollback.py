from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
)


def test_superseded_artifact_retains_previous_identity() -> None:
    artifact = ArtifactIdentity(
        model_class=ModelClass.CUSTOM,
        artifact_name="model",
        artifact_version="2",
        artifact_digest="f" * 64,
        source_uri="approved://model/2",
        license="Apache-2.0",
        approval_state=ArtifactApprovalState.APPROVED,
        approval_reference="approval-2",
        tenant_scope="tenant-a",
        classification="INTERNAL",
        processing_region="ap-southeast-1",
        training_identity_reference="train-1",
        inference_identity_reference="infer-1",
        supersedes="1" * 64,
    )
    assert artifact.supersedes == "1" * 64
