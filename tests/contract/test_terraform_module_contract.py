"""Static contract tests for the exact W5-001 Terraform module boundary."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SANDBOX = ROOT / "infra/environments/sandbox"
EXPECTED_INPUT_KEYS = (
    "aws_account_id",
    "aws_region",
    "w7_data_zone_prefixes",
    "w7_data_zone_retention_days",
    "aws_fallback_region",
    "network_ownership_mode",
    "vpc_id",
    "private_subnet_ids",
    "vpc_cidr",
    "private_subnet_cidrs",
    "dns_domain",
    "egress_mode",
    "vpc_endpoint_services",
    "w6_004_enabled",
    "bedrock_invocation_logging_enabled",
    "administrator_role_arn",
    "approval_expires_at",
    "approval_issued_at",
    "deployment_start",
    "owner_api_cidr",
    "eks_kubernetes_version",
    "eks_node_instance_types",
    "eks_addon_versions",
    "metrics_server_image",
    "otel_collector_image",
    "alert_email_endpoints",
    "w6_004_cost_ceiling_usd",
    "w6_004_stage_stop_limits_usd",
    "allow_public_ingress",
    "allow_nat_gateway",
    "mandatory_tags",
    "allowed_data_regions",
    "permitted_data_classifications",
    "monthly_budget_usd",
    "daily_budget_alert_usd",
    "max_paid_evaluation_usd",
    "kms_deletion_window_days",
    "kms_follow_up_owner",
    "github_organization",
    "github_organization_id",
    "github_repository",
    "github_repository_id",
    "github_environment",
    "github_oidc_role_name",
    "github_allowed_ref",
    "bedrock_model_id",
    "bedrock_region",
    "bedrock_access_status",
    "bedrock_fallback_policy",
)
EXPECTED_TFLINT_UNUSED_DECLARATION_EXCEPTIONS = (
    "aws_fallback_region",
    "network_ownership_mode",
    "vpc_id",
    "private_subnet_ids",
    "dns_domain",
    "allowed_data_regions",
    "permitted_data_classifications",
    "monthly_budget_usd",
    "daily_budget_alert_usd",
    "max_paid_evaluation_usd",
    "kms_follow_up_owner",
    "bedrock_region",
    "bedrock_access_status",
    "bedrock_fallback_policy",
)
MODULES = (
    "network",
    "kms",
    "storage",
    "secrets",
    "iam",
    "opensearch",
    "ecr",
    "eks",
    "observability",
)


def test_exact_49_key_tfvars_schema_is_preserved_without_az_key() -> None:
    source = (SANDBOX / "variables.tf").read_text(encoding="utf-8")
    variables = tuple(re.findall(r'^variable "([^"]+)"', source, flags=re.MULTILINE))

    assert variables == EXPECTED_INPUT_KEYS
    assert len(variables) == 49
    assert "availability_zones" not in variables
    assert 'allowed_data_regions == tolist(["Global Cross-Region"])' in source
    assert "aws_region must equal ap-southeast-1" in source

    type_safe_list_comparisons = (
        "private_subnet_cidrs == tolist([",
        "vpc_endpoint_services == tolist([",
        'allowed_data_regions == tolist(["Global Cross-Region"])',
        'permitted_data_classifications == tolist(["PUBLIC", "INTERNAL"])',
    )
    assert all(comparison in source for comparison in type_safe_list_comparisons)

    network_variables = (ROOT / "infra/modules/network/variables.tf").read_text(encoding="utf-8")
    network_main = (ROOT / "infra/modules/network/main.tf").read_text(encoding="utf-8")
    assert "availability_zones == tolist([" in network_variables
    assert "vpc_endpoint_services == tolist([" in network_main
    assert '"ec2:ModifyNetworkInterfaceAttribute",' in network_main
    assert '["sts:AssumeRole", "sts:GetCallerIdentity"]' in network_main


def test_only_approved_contract_inputs_suppress_tflint_unused_declarations() -> None:
    source = (SANDBOX / "variables.tf").read_text(encoding="utf-8")
    suppressed_variables = tuple(
        re.findall(
            r'^# tflint-ignore: terraform_unused_declarations\nvariable "([^"]+)"',
            source,
            flags=re.MULTILINE,
        )
    )

    assert suppressed_variables == EXPECTED_TFLINT_UNUSED_DECLARATION_EXCEPTIONS
    assert source.count("# tflint-ignore: terraform_unused_declarations") == len(
        EXPECTED_TFLINT_UNUSED_DECLARATION_EXCEPTIONS
    )
    assert "terraform_unused_declarations" not in (ROOT / ".tflint.hcl").read_text(encoding="utf-8")


def test_roots_pin_exact_terraform_and_aws_provider_bounds() -> None:
    bootstrap = ROOT / "infra/bootstrap/versions.tf"
    sandbox = SANDBOX / "versions.tf"
    for path in (bootstrap, sandbox):
        source = path.read_text(encoding="utf-8")
        assert 'required_version = "= 1.16.1"' in source
        assert 'source  = "hashicorp/aws"' in source
        assert 'version = "= 6.55.0"' in source
    assert 'organization = "Enterprise_AI_AWS_Arch"' in bootstrap.read_text(encoding="utf-8")
    assert 'name = "enterprise-ai-bootstrap"' in bootstrap.read_text(encoding="utf-8")
    assert 'organization = "Enterprise_AI_AWS_Arch"' in sandbox.read_text(encoding="utf-8")
    assert 'name = "enterprise-ai-sandbox"' in sandbox.read_text(encoding="utf-8")


def test_w12_private_codebuild_and_owner_gated_access_contract() -> None:
    sandbox = (SANDBOX / "main.tf").read_text(encoding="utf-8")
    iam = (ROOT / "infra/modules/iam/main.tf").read_text(encoding="utf-8")
    eks = (ROOT / "infra/modules/eks/main.tf").read_text(encoding="utf-8")
    assert 'resource "aws_codebuild_project" "capstone_deploy"' in sandbox
    assert "count                  = var.w12_capstone_enabled ? 1 : 0" in sandbox
    assert "concurrent_build_limit = 1" in sandbox
    assert 'source_identifier = "W12_CONTROL"' in sandbox
    assert 'resource "aws_iam_role" "capstone_build"' in iam
    assert 'resource "aws_iam_role" "capstone_deploy_caller"' in iam
    assert 'resource "aws_iam_role" "capstone_codebuild"' in iam
    assert "capstone_pki_role_arn" in eks


def test_every_approved_module_has_main_variables_and_outputs() -> None:
    for module in MODULES:
        directory = ROOT / "infra/modules" / module
        expected = {
            "main.tf",
            "outputs.tf",
            "variables.tf",
        }
        if module == "iam":
            expected.update({"w12_prerequisite_images.tf", "w12_prerequisite_outputs.tf"})
        assert {path.name for path in directory.glob("*.tf")} == expected


def test_fis_expiry_tag_does_not_force_template_replacement() -> None:
    source = (ROOT / "infra/modules/observability/main.tf").read_text(encoding="utf-8")
    fis = source.split('resource "aws_fis_experiment_template" "pod_delete" {', maxsplit=1)[1]

    assert "tags = var.tags" in fis
    assert 'ignore_changes = [tags["ExpiresAt"]]' in fis
    assert "ignore_changes = [tags]" not in fis


def test_sandbox_composes_exact_modules_and_zero_secrets() -> None:
    source = (SANDBOX / "main.tf").read_text(encoding="utf-8")
    assert tuple(re.findall(r'^module "([^"]+)"', source, flags=re.MULTILINE)) == MODULES
    assert "secret_names = []" in source
    assert 'availability_zones = ["ap-southeast-1a", "ap-southeast-1b"]' in source
    assert 'var.mandatory_tags["ExpiresAt"] != "TODO_OWNER"' in source
    assert "opensearch_log_group_arns = [" in source
    for suffix in (
        "application-logs",
        "audit-logs",
        "index-slow-logs",
        "search-slow-logs",
    ):
        assert (
            "arn:aws:logs:${var.aws_region}:${var.aws_account_id}:log-group:"
            "/aws/OpenSearchService/domains/${local.opensearch_domain}/"
            f"{suffix}"
        ) in source


def test_state_bucket_lifecycle_aborts_incomplete_uploads_without_expiring_state() -> None:
    source = (ROOT / "infra/bootstrap/main.tf").read_text(encoding="utf-8")
    lifecycle = source.split(
        'resource "aws_s3_bucket_lifecycle_configuration" "terraform_state"', maxsplit=1
    )[1].split(
        'resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state"',
        maxsplit=1,
    )[0]

    assert "days_after_initiation = 7" in lifecycle
    assert "expiration" not in lifecycle


def test_backend_example_uses_exact_owner_approved_boundary() -> None:
    source = (SANDBOX / "backend.hcl.example").read_text(encoding="utf-8")
    assert (
        'bucket         = "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"'
        in source
    )
    assert 'key            = "sandbox/platform.tfstate"' in source
    assert re.search(r"(?m)^use_lockfile\s*=\s*true\s*$", source)
    assert "dynamodb_table" not in source
    assert 'kms_key_id     = "alias/enterprise-ai-platform-sandbox-terraform-state"' in source


def test_github_repository_identity_produces_the_exact_immutable_oidc_subject() -> None:
    tfvars = (SANDBOX / "terraform.tfvars.example").read_text(encoding="utf-8")
    variables = (SANDBOX / "variables.tf").read_text(encoding="utf-8")
    iam = (ROOT / "infra/modules/iam/main.tf").read_text(encoding="utf-8")

    values = dict(
        re.findall(
            r'^(github_(?:organization|organization_id|repository|repository_id|environment))\s*=\s*"([^"]+)"$',
            tfvars,
            flags=re.MULTILINE,
        )
    )
    assert values == {
        "github_organization": "gprai",
        "github_organization_id": "82297871",
        "github_repository": "enterprize_ai_platform",
        "github_repository_id": "1340913005",
        "github_environment": "sandbox",
    }
    subject = (
        f"repo:{values['github_organization']}@{values['github_organization_id']}/"
        f"{values['github_repository']}@{values['github_repository_id']}:"
        f"environment:{values['github_environment']}"
    )
    assert subject == "repo:gprai@82297871/enterprize_ai_platform@1340913005:environment:sandbox"
    assert 'var.github_organization_id == "82297871"' in variables
    assert 'var.github_repository == "enterprize_ai_platform"' in variables
    assert 'var.github_repository_id == "1340913005"' in variables
    assert "github_repository must equal enterprize_ai_platform" in variables
    assert (
        'github_repository_subject = "repo:${var.github_organization}@'
        "${var.github_organization_id}/"
        '${var.github_repository}@${var.github_repository_id}"' in iam
    )
    assert '"${local.github_repository_subject}:environment:${var.github_environment}"' in iam
    assert '"${local.github_repository_subject}:ref:refs/heads/main"' in iam


def test_future_backend_contract_rejects_deprecated_or_dual_locking() -> None:
    from tools.platformctl.contracts import ContractError
    from tools.platformctl.plan_artifact_producer import _backend_bytes

    valid = {
        "bucket": "state-bucket",
        "key": "sandbox/platform.tfstate",
        "region": "ap-southeast-1",
        "use_lockfile": True,
        "encrypt": True,
        "kms_key_id": "alias/state",
    }
    assert b"use_lockfile = true" in _backend_bytes(valid)
    with pytest.raises(ContractError, match="LOCKFILE"):
        _backend_bytes({**valid, "dynamodb_table": "historical-lock-table"})


def test_w7_existing_bucket_zones_and_notification_are_declared_once() -> None:
    storage = (ROOT / "infra/modules/storage/main.tf").read_text(encoding="utf-8")
    variables = (ROOT / "infra/modules/storage/variables.tf").read_text(encoding="utf-8")
    sandbox = (ROOT / "infra/environments/sandbox/main.tf").read_text(encoding="utf-8")
    assert storage.count('resource "aws_s3_bucket" "this"') == 1
    assert storage.count('resource "aws_s3_bucket_notification" "eventbridge"') == 1
    assert "eventbridge = true" in storage
    for prefix in ("raw/", "quarantine/", "processed/", "evidence/"):
        assert prefix in variables
    assert "w7_data_zone_prefixes" in sandbox
    assert "w7_data_zone_retention_days" in sandbox


def test_storage_noncurrent_retention_is_parameterized() -> None:
    storage = (ROOT / "infra/modules/storage/main.tf").read_text()
    variables = (ROOT / "infra/modules/storage/variables.tf").read_text()
    assert "noncurrent_days = var.noncurrent_version_retention_days" in storage
    assert 'variable "noncurrent_version_retention_days"' in variables
    assert "default     = 30" in variables


def test_sandbox_storage_noncurrent_retention_is_180_days() -> None:
    sandbox = (ROOT / "infra/environments/sandbox/main.tf").read_text()
    assert "noncurrent_version_retention_days = 180" in sandbox
    assert sandbox.count("noncurrent_version_retention_days = 180") == 1
