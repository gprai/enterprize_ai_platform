from __future__ import annotations

from typing import Any

import pytest
from provision.cleanup import purge_ecr, retained, validate_destroy
from provision.services import ServiceError


class Registry:
    def __init__(self) -> None:
        self.entries = {
            "sha256:index": "application/vnd.oci.image.index.v1+json",
            "sha256:child": "image",
        }
        self.batches: list[list[str]] = []

    def get_paginator(self, operation: str) -> Registry:
        assert operation == "describe_images"
        return self

    def paginate(self, **kwargs: Any) -> list[dict[str, Any]]:
        return [
            {"imageDetails": [{"imageDigest": d, "imageManifestMediaType": m}]}
            for d, m in self.entries.items()
        ]

    def batch_delete_image(self, **kwargs: Any) -> dict[str, Any]:
        batch = [i["imageDigest"] for i in kwargs["imageIds"]]
        self.batches.append(batch)
        for digest in batch:
            del self.entries[digest]
        return {"imageIds": kwargs["imageIds"]}


def test_ecr_purge_deletes_manifest_indexes_then_children_and_relists() -> None:
    registry = Registry()
    checks = []
    result = purge_ecr(registry, [{"name": "enterprise-ai/sandbox/api"}], lambda: checks.append(1))
    assert registry.batches == [["sha256:index"], ["sha256:child"]]
    assert result == {"enterprise-ai/sandbox/api": 2}
    assert not registry.entries and len(checks) >= 3


def test_ecr_purge_stops_on_access_denied(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = Registry()
    monkeypatch.setattr(
        registry, "batch_delete_image", lambda **k: {"failures": [{"failureCode": "AccessDenied"}]}
    )
    with pytest.raises(ServiceError, match="ECR_PURGE_FAILED"):
        purge_ecr(registry, [{"name": "enterprise-ai/sandbox/api"}], lambda: None)


def test_separate_bootstrap_destroy_boundary_accepts_only_reviewed_targets() -> None:
    step = {"targets": ["aws_iam_role.platform"], "target": "bootstrap"}
    validate_destroy(
        {
            "resource_changes": [
                {
                    "mode": "managed",
                    "address": "aws_iam_role.platform",
                    "type": "aws_iam_role",
                    "change": {"actions": ["delete"], "before": {"id": "role"}},
                }
            ]
        },
        step,
    )
    assert step["native_targets"][0]["id"] == "role"
    assert retained("aws_iam_role") and retained("aws_kms_key") and retained("aws_s3_bucket_policy")
