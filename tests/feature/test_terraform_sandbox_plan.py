"""Static feature contract for the future owner-executed sandbox plan."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_exact_storage_ecr_and_opensearch_sandbox_values_are_encoded() -> None:
    sandbox = (ROOT / "infra/environments/sandbox/main.tf").read_text(encoding="utf-8")
    storage = (ROOT / "infra/modules/storage/main.tf").read_text(encoding="utf-8")
    ecr = (ROOT / "infra/modules/ecr/main.tf").read_text(encoding="utf-8")
    opensearch = (ROOT / "infra/modules/opensearch/main.tf").read_text(encoding="utf-8")
    storage_lines = tuple(line.strip() for line in storage.splitlines())

    assert (
        'platform_bucket    = "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"'
        in sandbox
    )
    assert 'opensearch_domain  = "enterprise-ai-sandbox"' in sandbox
    assert 'engine_version         = "OpenSearch_2.19"' in sandbox
    assert 'instance_type          = "t3.small.search"' in sandbox
    assert "days_after_initiation = 7" in storage
    assert storage_lines.count("days = 30") == 2
    assert storage_lines.count("noncurrent_days = var.noncurrent_version_retention_days") == 1
    assert "default     = 30" in (ROOT / "infra/modules/storage/variables.tf").read_text(
        encoding="utf-8"
    )
    assert 'prefix = "tmp/"' in storage and 'prefix = "test/"' in storage
    assert 'image_tag_mutability = "IMMUTABLE"' in ecr
    assert "countNumber = var.retained_image_count" in ecr
    assert (
        sum(
            line.split() == ["kms_key_id", "=", "var.kms_key_arn"]
            for line in opensearch.splitlines()
        )
        == 2
    )


def test_exact_role_and_trust_boundaries_are_encoded() -> None:
    source = (ROOT / "infra/bootstrap/modules/platform-iam/main.tf").read_text(encoding="utf-8")

    for role in (
        "enterprise-ai-sandbox-runtime",
        "enterprise-ai-sandbox-ingestion",
        "enterprise-ai-sandbox-opensearch-admin",
    ):
        assert role in source
    assert 'identifiers = ["pods.eks.amazonaws.com"]' in source
    assert 'values   = ["2026-09-30T15:59:59Z"]' not in source
    assert "var.administrator_trust_expires_at" in source
    assert "aws_eks_pod_identity_association" not in source
    assert "oidc-provider/token.actions.githubusercontent.com" in source


def test_policy_as_code_uses_only_inline_synthetic_plan_inputs() -> None:
    policy = (ROOT / "policies/opa/terraform_plan.rego").read_text(encoding="utf-8")
    tests = (ROOT / "policies/opa/terraform_plan_test.rego").read_text(encoding="utf-8")

    assert "package enterprise_ai.terraform.plan" in policy
    assert "package enterprise_ai.terraform.plan" in tests
    assert "resource_changes" in tests
    assert "terraform.tfplan" not in tests
    assert "terraform show" not in tests
    assert "http.send" not in policy + tests


def test_w7_plan_source_uses_existing_bucket_and_exact_retention_contract() -> None:
    storage = (ROOT / "infra/modules/storage/main.tf").read_text(encoding="utf-8")
    variables = (ROOT / "infra/environments/sandbox/variables.tf").read_text(encoding="utf-8")
    iam = (ROOT / "infra/bootstrap/modules/platform-iam/main.tf").read_text(encoding="utf-8")
    assert storage.count('resource "aws_s3_bucket"') == 1
    assert 'resource "aws_s3_bucket_notification" "eventbridge"' in storage
    for expected in (
        "raw        = 7",
        "quarantine = 7",
        "processed  = 30",
        "evidence   = 30",
    ):
        assert expected in variables
    assert "RuntimeReadGovernedObjects" in iam
    assert "IngestionWriteQuarantineObjects" in iam
