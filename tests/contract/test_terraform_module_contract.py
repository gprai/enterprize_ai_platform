"""Static contract tests for the exact W5-001 Terraform module boundary."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SANDBOX = ROOT / "infra/environments/sandbox"
EXPECTED_INPUT_KEYS = (
    "aws_account_id",
    "aws_region",
    "aws_fallback_region",
    "network_ownership_mode",
    "vpc_id",
    "private_subnet_ids",
    "vpc_cidr",
    "private_subnet_cidrs",
    "dns_domain",
    "egress_mode",
    "vpc_endpoint_services",
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
    "github_repository",
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
MODULES = ("network", "kms", "storage", "secrets", "iam", "opensearch", "ecr")


def test_exact_30_key_tfvars_schema_is_preserved_without_az_key() -> None:
    source = (SANDBOX / "variables.tf").read_text(encoding="utf-8")
    variables = tuple(re.findall(r'^variable "([^"]+)"', source, flags=re.MULTILINE))

    assert variables == EXPECTED_INPUT_KEYS
    assert len(variables) == 30
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
    for path in (ROOT / "infra/bootstrap/versions.tf", SANDBOX / "versions.tf"):
        source = path.read_text(encoding="utf-8")
        assert 'required_version = ">= 1.5, < 2.0"' in source
        assert 'source  = "hashicorp/aws"' in source
        assert 'version = "~> 6.55.0"' in source


def test_every_approved_module_has_main_variables_and_outputs() -> None:
    for module in MODULES:
        directory = ROOT / "infra/modules" / module
        assert {path.name for path in directory.glob("*.tf")} == {
            "main.tf",
            "outputs.tf",
            "variables.tf",
        }


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
    assert 'dynamodb_table = "enterprise-ai-platform-sandbox-tflock"' in source
    assert 'kms_key_id     = "alias/enterprise-ai-platform-sandbox-terraform-state"' in source


def test_github_repository_identity_produces_the_exact_oidc_subject() -> None:
    tfvars = (SANDBOX / "terraform.tfvars.example").read_text(encoding="utf-8")
    variables = (SANDBOX / "variables.tf").read_text(encoding="utf-8")
    iam = (ROOT / "infra/modules/iam/main.tf").read_text(encoding="utf-8")

    values = dict(
        re.findall(
            r'^(github_(?:organization|repository|environment))\s*=\s*"([^"]+)"$',
            tfvars,
            flags=re.MULTILINE,
        )
    )
    assert values == {
        "github_organization": "gprai",
        "github_repository": "enterprize_ai_platform",
        "github_environment": "sandbox",
    }
    subject = (
        f"repo:{values['github_organization']}/{values['github_repository']}:"
        f"environment:{values['github_environment']}"
    )
    assert subject == "repo:gprai/enterprize_ai_platform:environment:sandbox"
    assert 'var.github_repository == "enterprize_ai_platform"' in variables
    assert "github_repository must equal enterprize_ai_platform" in variables
    assert (
        "repo:${var.github_organization}/${var.github_repository}:"
        "environment:${var.github_environment}" in iam
    )
