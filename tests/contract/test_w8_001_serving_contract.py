from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
)


def valid_artifact() -> ArtifactIdentity:
    return ArtifactIdentity(
        model_class=ModelClass.CUSTOM,
        artifact_name="model",
        artifact_version="1",
        artifact_digest="b" * 64,
        source_uri="approved://model/1",
        license="MIT",
        approval_state=ArtifactApprovalState.APPROVED,
        approval_reference="approval-1",
        tenant_scope="tenant-a",
        classification="INTERNAL",
        processing_region="ap-southeast-1",
        training_identity_reference="train-1",
        inference_identity_reference="infer-1",
    )


def test_canonical_digest_is_stable() -> None:
    first = valid_artifact()
    second = ArtifactIdentity.model_validate(first.model_dump(mode="python"), strict=True)
    assert first.canonical_bytes() == second.canonical_bytes()
    assert first.canonical_digest() == second.canonical_digest()


def test_extra_identity_fields_are_rejected() -> None:
    values = valid_artifact().model_dump(mode="python")
    values["unexpected"] = "reject"
    with pytest.raises(ValidationError):
        ArtifactIdentity.model_validate(values, strict=True)
