"""Static W5-001 Terraform security and wildcard reconciliation tests."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INFRA = ROOT / "infra"

EXPECTED_CHECKOV_SKIPS = {
    ("infra/bootstrap/main.tf", "CKV_AWS_18"),
    ("infra/bootstrap/main.tf", "CKV_AWS_109"),
    ("infra/bootstrap/main.tf", "CKV_AWS_111"),
    ("infra/bootstrap/main.tf", "CKV_AWS_144"),
    ("infra/bootstrap/main.tf", "CKV_AWS_356"),
    ("infra/bootstrap/main.tf", "CKV2_AWS_62"),
    ("infra/modules/kms/main.tf", "CKV_AWS_109"),
    ("infra/modules/kms/main.tf", "CKV_AWS_111"),
    ("infra/modules/kms/main.tf", "CKV_AWS_356"),
    ("infra/modules/eks/main.tf", "CKV_AWS_39"),
    ("infra/modules/iam/main.tf", "CKV_AWS_111"),
    ("infra/modules/iam/main.tf", "CKV_AWS_355"),
    ("infra/modules/observability/main.tf", "CKV_AWS_158"),
    ("infra/modules/observability/main.tf", "CKV_AWS_338"),
    ("infra/modules/network/main.tf", "CKV2_AWS_11"),
    ("infra/modules/opensearch/main.tf", "CKV_AWS_318"),
    ("infra/modules/opensearch/main.tf", "CKV_AWS_338"),
    ("infra/modules/opensearch/main.tf", "CKV2_AWS_59"),
    ("infra/modules/secrets/main.tf", "CKV2_AWS_57"),
    ("infra/modules/storage/main.tf", "CKV_AWS_18"),
    ("infra/modules/storage/main.tf", "CKV_AWS_144"),
}


def terraform_source() -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in INFRA.rglob("*.tf"))


def test_prohibited_action_wildcards_and_permissions_are_absent() -> None:
    source = terraform_source()
    for prohibited in (
        '"kms:*"',
        '"kms:GenerateDataKey*"',
        '"kms:ReEncrypt*"',
        '"es:ESHttp*"',
        '"logs:*"',
        "servicequotas:",
        "iam:List",
        "iam:Describe",
    ):
        assert prohibited not in source
    network = (INFRA / "modules/network/main.tf").read_text(encoding="utf-8")
    assert source.count('"ecr:GetAuthorizationToken"') == 3
    assert network.count('"ecr:GetAuthorizationToken"') == 2
    assert '"ECR API" = [' in network
    assert '"ECR DKR" = [' in network


def test_only_approved_resource_and_principal_wildcards_exist() -> None:
    source = terraform_source()
    assert source.count('resources = ["*"]') == 14
    assert source.count('identifiers = ["*"]') == 5
    network = (INFRA / "modules/network/main.tf").read_text(encoding="utf-8")
    assert network.count('identifiers = ["*"]') == 3
    assert network.count('variable = "aws:PrincipalAccount"') == 2
    assert network.count("values   = [var.aws_account_id]") == 2
    assert 'sid       = "AllowEcrLayerDownloads"' in network
    assert 'actions   = ["s3:GetObject"]' in network
    assert 'resources = ["arn:aws:s3:::prod-${var.aws_region}-starport-layer-bucket/*"]' in network
    assert (
        "arn:aws:s3:::enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1/*"
        not in source
    )
    assert '"${local.state_bucket_arn}/*"' in source
    for prefix in ("raw", "quarantine", "processed", "evidence"):
        assert (
            f'"${{local.platform_bucket_arn}}/${{var.data_zone_prefixes["{prefix}"]}}*"' in source
        )
    assert '"${local.domain_arn}/*"' in source


def test_dynamodb_create_grant_is_exactly_account_and_service_bounded() -> None:
    source = (INFRA / "bootstrap/main.tf").read_text(encoding="utf-8")
    grant_statement = source.split('sid    = "AllowExactAccountDynamoDBStateGrant"', maxsplit=1)[
        1
    ].split("\n  }\n}", maxsplit=1)[0]

    assert source.count('"kms:CreateGrant"') == 1
    assert 'identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]' in grant_statement
    assert 'actions   = ["kms:CreateGrant"]' in grant_statement
    assert 'resources = ["*"]' in grant_statement
    assert 'variable = "kms:CallerAccount"' in grant_statement
    assert "values   = [var.aws_account_id]" in grant_statement
    assert 'variable = "kms:ViaService"' in grant_statement
    assert 'values   = ["dynamodb.*.amazonaws.com"]' in grant_statement
    assert 'identifiers = ["*"]' not in grant_statement


def test_exact_opensearch_log_stream_wildcards_are_conditioned() -> None:
    source = (INFRA / "modules/opensearch/main.tf").read_text(encoding="utf-8")
    for suffix in ("application-logs:*", "audit-logs:*", "index-slow-logs:*", "search-slow-logs:*"):
        assert f"enterprise-ai-sandbox/{suffix}" in source
    assert 'identifiers = ["es.amazonaws.com"]' in source
    assert 'actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]' in source
    assert 'variable = "aws:SourceAccount"' in source
    assert 'variable = "aws:SourceArn"' in source


def test_exact_cloudwatch_logs_kms_access_is_bounded() -> None:
    source = (INFRA / "modules/kms/main.tf").read_text(encoding="utf-8")
    grant_statement = source.split('sid    = "AllowExactOpenSearchLogEncryption"', maxsplit=1)[
        1
    ].split("\n  }\n}", maxsplit=1)[0]

    assert 'identifiers = ["logs.ap-southeast-1.amazonaws.com"]' in grant_statement
    assert 'variable = "kms:EncryptionContext:aws:logs:arn"' in grant_statement
    assert "values   = var.opensearch_log_group_arns" in grant_statement
    assert 'variable = "kms:ViaService"' not in grant_statement
    for action in (
        "kms:Decrypt",
        "kms:DescribeKey",
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:ReEncryptFrom",
        "kms:ReEncryptTo",
    ):
        assert f'"{action}"' in grant_statement


def test_only_exact_owner_reviewed_checkov_skips_exist() -> None:
    found: set[tuple[str, str]] = set()

    for path in INFRA.rglob("*.tf"):
        relative_path = path.relative_to(ROOT).as_posix()
        for line in path.read_text(encoding="utf-8").splitlines():
            if "#checkov:skip=" not in line:
                continue
            match = re.fullmatch(r"\s*#checkov:skip=([^:]+):(.+)", line)
            assert match is not None
            assert match.group(2).strip()
            found.add((relative_path, match.group(1)))

    assert found == EXPECTED_CHECKOV_SKIPS


def test_no_public_or_nat_network_resource_is_declared() -> None:
    source = terraform_source()
    assert 'resource "aws_nat_gateway"' not in source
    assert 'resource "aws_internet_gateway"' not in source
    assert "0.0.0.0/0" not in source
    assert "::/0" not in source
    assert "map_public_ip_on_launch = false" in source
    assert "enforce_https       = true" in source
    assert 'resource "aws_default_security_group" "restricted"' in source
    assert "ingress = []" in source
    assert "egress  = []" in source


def test_secrets_module_has_no_value_bearing_surface() -> None:
    directory = INFRA / "modules/secrets"
    source = "\n".join(path.read_text(encoding="utf-8") for path in directory.glob("*.tf"))
    assert 'resource "aws_secretsmanager_secret_version"' not in source
    for prohibited in ('variable "secret_value"', 'variable "password"', 'variable "token"'):
        assert prohibited not in source


def test_w7_prefix_access_prevents_raw_or_quarantine_retrieval() -> None:
    source = (INFRA / "modules/iam/main.tf").read_text(encoding="utf-8")
    runtime = source.split('data "aws_iam_policy_document" "runtime"', maxsplit=1)[1].split(
        'resource "aws_iam_role_policy" "runtime"', maxsplit=1
    )[0]
    ingestion = source.split('data "aws_iam_policy_document" "ingestion"', maxsplit=1)[1]
    assert 'var.data_zone_prefixes["raw"]' not in runtime
    assert 'var.data_zone_prefixes["quarantine"]' not in runtime
    assert 'var.data_zone_prefixes["processed"]' in runtime
    assert 'var.data_zone_prefixes["evidence"]' in runtime
    quarantine = ingestion.split('"IngestionWriteQuarantineObjects"', maxsplit=1)[1].split(
        "\n  }", maxsplit=1
    )[0]
    assert '"s3:GetObject"' not in quarantine
    assert '"s3:PutObject"' in quarantine
