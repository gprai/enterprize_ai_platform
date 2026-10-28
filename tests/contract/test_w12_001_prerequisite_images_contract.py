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
    assert workflow.index("Assume only the read-only Public ECR role") < workflow.index(
        "Authenticate only to Public ECR"
    )
    assert workflow.index("Authenticate only to Public ECR") < workflow.index(
        "Build both pinned Linux AMD64 images"
    )
    assert workflow.index("Build both pinned Linux AMD64 images") < workflow.index(
        "Remove temporary Public ECR authentication"
    )
    assert workflow.index("Scan both final images") < workflow.index("Assume only the dedicated")
    assert workflow.index("Assume only the dedicated") < workflow.index("Push only scanned images")
    assert "aws ecr-public get-login-password --region us-east-1" in workflow
    assert "docker login --username AWS --password-stdin public.ecr.aws" in workflow
    public_config = workflow.index('public_config="$RUNNER_TEMP/w12-public-ecr-docker-config"')
    export_config = workflow.index('export DOCKER_CONFIG="$public_config"')
    persist_config = workflow.index('echo "DOCKER_CONFIG=$public_config" >> "$GITHUB_ENV"')
    public_login = workflow.index("docker login --username AWS --password-stdin public.ecr.aws")
    assert public_config < export_config < persist_config < public_login
    assert "tools/w12_001_images.py" in workflow
    assert "--exception configs/ci/w12-001-image-scan-exception.json" in workflow
    assert "--source-manifest images/w12/pinned-inputs.json" in workflow
    assert "describe-repositories" in workflow
    assert "get-lifecycle-policy" in workflow
    assert "$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT" in workflow
    assert "imageDetails[0].imageDigest" in workflow
    assert "imagetools inspect" in workflow


def test_scan_exception_is_exact_and_time_bounded() -> None:
    exception = json.loads(_source("configs/ci/w12-001-image-scan-exception.json"))
    source = (ROOT / "images/w12/pinned-inputs.json").read_bytes()
    assert exception["schema_version"] == "w12-001.exact-image-scan-exception.v1"
    assert (
        exception["pinned_source_manifest_sha256"]
        == hashlib.sha256(source.replace(b"\r\n", b"\n")).hexdigest()
    )
    assert exception["approved_at_utc"] == "2026-10-26T06:17:36Z"
    assert exception["expires_at_utc"] == "2026-11-02T06:17:36Z"
    assert set(exception["images"]) == {"toolchain", "codebuild"}
    assert {
        name: {scanner: details["high_critical_count"] for scanner, details in scans.items()}
        for name, scans in exception["images"].items()
    } == {
        "toolchain": {"trivy": 145, "grype": 202},
        "codebuild": {"trivy": 84, "grype": 131},
    }
    for scans in exception["images"].values():
        assert set(scans) == {"trivy", "grype"}
        assert all(len(details["finding_sha256"]) == 64 for details in scans.values())


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
    assert "${local.github_repository_subject}:environment:${var.github_environment}" in trust
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


def test_public_ecr_reader_is_token_only_and_uses_exact_environment_trust() -> None:
    iam = _source("infra/modules/iam/w12_prerequisite_images.tf")
    reader = iam.split('data "aws_iam_policy_document" "w12_public_ecr_reader"', 1)[1]
    reader = reader.split('resource "aws_iam_role_policy" "w12_public_ecr_reader"', 1)[0]
    assert 'actions   = ["ecr-public:GetAuthorizationToken"]' in reader
    assert 'actions   = ["sts:GetServiceBearerToken"]' in reader
    assert 'variable = "sts:AWSServiceName"' not in reader
    assert 'values   = ["ecr-public.amazonaws.com"]' not in reader
    assert reader.count('resources = ["*"]') == 2
    assert "ecr:PutImage" not in reader
    assert "ecr:InitiateLayerUpload" not in reader
    assert "ecr:UploadLayerPart" not in reader
    role = iam.split('resource "aws_iam_role" "w12_public_ecr_reader"', 1)[1]
    role = role.split('data "aws_iam_policy_document" "w12_public_ecr_reader"', 1)[0]
    assert 'name               = "enterprise-ai-w12-public-ecr-reader"' in role
    assert "data.aws_iam_policy_document.w12_image_publisher_trust.json" in role
