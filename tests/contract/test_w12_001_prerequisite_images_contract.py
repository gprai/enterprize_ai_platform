"""Source contracts for the inert W12 prerequisite image publication path."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _source(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_reviewed_recipes_are_bound_to_the_saved_input_manifest() -> None:
    root = ROOT / "images/w12"
    manifest = json.loads((root / "pinned-inputs.json").read_text(encoding="utf-8"))
    assert manifest["platform"] == "linux/amd64"
    assert {entry["name"] for entry in manifest["recipes"]} == {
        "toolchain.Dockerfile",
        "codebuild.Dockerfile",
        "codebuild-requirements.lock",
    }
    for entry in manifest["recipes"]:
        contents = (root / entry["name"]).read_bytes()
        assert len(contents) == entry["bytes"]
        assert hashlib.sha256(contents).hexdigest() == entry["sha256"]
    assert "@sha256:" in _source("images/w12/toolchain.Dockerfile")
    assert "@sha256:" in _source("images/w12/codebuild.Dockerfile")
    assert "--require-hashes" in _source("images/w12/codebuild.Dockerfile")


def test_two_distinct_terraform_managed_prerequisite_repositories() -> None:
    sandbox = _source("infra/environments/sandbox/w12_prerequisite_images.tf")
    module = _source("infra/modules/ecr/main.tf")
    allowed = _source("infra/modules/ecr/variables.tf")
    assert 'module "w12_toolchain_ecr"' in sandbox
    assert 'module "w12_codebuild_ecr"' in sandbox
    assert 'module "ecr"' in _source("infra/environments/sandbox/main.tf")
    for name in ("w12-toolchain", "w12-codebuild"):
        assert f"enterprise-ai/sandbox/{name}" in sandbox
        assert f"enterprise-ai/sandbox/{name}" in allowed
    assert 'image_tag_mutability = "IMMUTABLE"' in module
    assert "scan_on_push = true" in module
    assert 'encryption_type = "KMS"' in module
    assert 'resource "aws_ecr_lifecycle_policy"' in module
    assert "tags = var.tags" in module


def test_manual_workflow_scans_before_assumption_or_push() -> None:
    workflow = _source(".github/workflows/w12-prerequisite-images.yml")
    assert "workflow_dispatch:" in workflow
    assert "pull_request:" not in workflow
    assert "push:" not in workflow
    assert "environment: sandbox" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "git rev-parse HEAD" in workflow
    assert workflow.index("Scan both final images") < workflow.index("Assume only the dedicated")
    assert workflow.index("Assume only the dedicated") < workflow.index("Push only scanned images")
    assert "tools/w12_001_images.py" in workflow
    assert "describe-repositories" in workflow
    assert "get-lifecycle-policy" in workflow
    assert "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" in workflow
    assert "imageDetails[0].imageDigest" in workflow
    assert "imagetools inspect" in workflow


def test_dedicated_publisher_and_exact_codebuild_pull() -> None:
    iam = _source("infra/modules/iam/w12_prerequisite_images.tf")
    publisher = iam.split('data "aws_iam_policy_document" "w12_image_publisher"', 1)[1]
    publisher = publisher.split('resource "aws_iam_role_policy" "w12_image_publisher"', 1)[0]
    assert "local.w12_toolchain_ecr_arn" in publisher
    assert "local.w12_codebuild_ecr_arn" in publisher
    assert "local.capstone_ecr_arn" not in publisher
    assert "ecr:DescribeRepositories" in publisher
    assert "ecr:GetLifecyclePolicy" in publisher
    trust = iam.split('data "aws_iam_policy_document" "w12_image_publisher_trust"', 1)[1]
    trust = trust.split('resource "aws_iam_role" "w12_image_publisher"', 1)[0]
    assert (
        "repo:${var.github_organization}/${var.github_repository}:environment:${var.github_environment}"
        in trust
    )
    codebuild = iam.split('data "aws_iam_policy_document" "w12_codebuild_executor_pull"', 1)[1]
    codebuild = codebuild.split('resource "aws_iam_role_policy" "w12_codebuild_executor_pull"', 1)[
        0
    ]
    assert "ecr:BatchCheckLayerAvailability" in codebuild
    assert "ecr:BatchGetImage" in codebuild
    assert "ecr:GetDownloadUrlForLayer" in codebuild
    assert "local.w12_codebuild_ecr_arn" in codebuild
    assert "local.w12_toolchain_ecr_arn" not in codebuild
    assert "role   = aws_iam_role.capstone_codebuild.id" in iam
