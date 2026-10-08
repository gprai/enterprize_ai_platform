from hashlib import sha256
from pathlib import Path

import pytest
from tools.platformctl import policy_runner
from tools.platformctl.kubernetes_lifecycle import validate_kubernetes_evidence
from tools.platformctl.live_validation import W6004Error, canonical_sha256

from tests.fakes.w6_004_lifecycle import kubernetes_evidence

ROOT = Path(__file__).resolve().parents[2]


def test_private_network_and_immutable_images_are_mandatory() -> None:
    policy = (ROOT / "deploy/k8s/networkpolicy.yaml").read_text(encoding="utf-8")
    assert "10.60.0.0/16" in policy
    assert "169.254.170.23/32" in policy
    assert "0.0.0.0/0" not in policy
    assert validate_kubernetes_evidence(kubernetes_evidence())["status"] == "PASS"


def test_vpc_cni_enforces_network_policy() -> None:
    eks = (ROOT / "infra/modules/eks/main.tf").read_text(encoding="utf-8")
    assert 'each.key == "vpc-cni" ? jsonencode({ enableNetworkPolicy = "true" }) : null' in eks


def test_resource_expiry_can_outlive_mutation_but_not_governance() -> None:
    sandbox = (ROOT / "infra/environments/sandbox/main.tf").read_text(encoding="utf-8")
    assert 'timecmp(var.mandatory_tags["ExpiresAt"], var.approval_expires_at) >= 0' in sandbox
    assert 'timeadd(var.approval_issued_at, "24h")' in sandbox
    assert 'timeadd(var.deployment_start, "24h")' in sandbox
    assert 'timeadd(var.deployment_start, "8h")' not in sandbox
    assert 'var.mandatory_tags["ExpiresAt"] == var.approval_expires_at' not in sandbox


def test_sandbox_auth_secret_is_mounted_as_a_read_only_file() -> None:
    deployment = (ROOT / "deploy/k8s/deployment.yaml").read_text(encoding="utf-8")
    assert "secretKeyRef" not in deployment
    assert "ENTERPRISE_AI_SANDBOX_AUTH_SIGNING_KEY:" not in deployment
    assert "ENTERPRISE_AI_SANDBOX_AUTH_SIGNING_KEY_FILE" in deployment
    assert "mountPath: /var/run/secrets/enterprise-ai" in deployment
    assert "readOnly: true" in deployment
    assert "defaultMode: 0440" in deployment


def test_static_iam_user_is_not_in_sandbox_composition() -> None:
    sandbox = (ROOT / "infra/environments/sandbox/main.tf").read_text(encoding="utf-8")
    terraform = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted((ROOT / "infra").rglob("*.tf"))
    )
    assert 'resource "aws_iam_user"' not in terraform
    assert 'resource "aws_iam_access_key"' not in terraform
    assert 'resource "aws_iam_user_policy"' not in terraform
    assert 'resource "aws_iam_user_policy_attachment"' not in terraform
    assert '!can(regex("(?i)finopsinfra", var.administrator_role_arn))' in sandbox


def test_runtime_and_ingestion_identity_permissions_remain_separate() -> None:
    text = (ROOT / "infra/modules/iam/main.tf").read_text(encoding="utf-8")
    assert (
        'opensearch_index_root_arn = "${local.opensearch_domain_arn}/enterprise_ai_sandbox"' in text
    )
    assert text.count("local.opensearch_index_root_arn,") == 2
    runtime = text.split('data "aws_iam_policy_document" "runtime" {', 1)[1].split(
        'resource "aws_iam_role_policy" "runtime"', 1
    )[0]
    ingestion = text.split('data "aws_iam_policy_document" "ingestion" {', 1)[1]
    assert 'sid    = "RuntimeOpenSearchExactIndexQuery"' in runtime
    assert '"es:ESHttpDelete"' not in runtime
    assert '"es:ESHttpPatch"' not in runtime
    assert '"es:ESHttpPut"' not in runtime
    assert 'sid    = "IngestionOpenSearchDataPlane"' in ingestion
    assert '"es:ESHttpDelete"' in ingestion
    assert '"es:ESHttpPut"' in ingestion


def test_opensearch_resource_policy_grants_runtime_only_exact_read_paths() -> None:
    text = (ROOT / "infra/modules/opensearch/main.tf").read_text(encoding="utf-8")
    domain_access = text.split('data "aws_iam_policy_document" "domain_access" {', 1)[1].split(
        'resource "aws_opensearch_domain" "this"', 1
    )[0]
    assert 'sid    = "RuntimeExactReadAccess"' in domain_access
    runtime = domain_access.split('sid    = "RuntimeExactReadAccess"', 1)[1]
    assert "var.runtime_role_arn" in runtime
    assert '"es:ESHttpGet"' in runtime
    assert '"es:ESHttpHead"' in runtime
    assert '"es:ESHttpPost"' in runtime
    assert '"es:ESHttpDelete"' not in runtime
    assert '"es:ESHttpPatch"' not in runtime
    assert '"es:ESHttpPut"' not in runtime
    assert '"${local.domain_arn}/_cluster/health"' in runtime
    assert '"${local.domain_arn}/enterprise_ai_sandbox"' in runtime
    assert '"${local.domain_arn}/enterprise_ai_sandbox/*"' in runtime
    assert "var.ingestion_role_arn" in domain_access
    assert "var.administrator_role_arn" in domain_access


def test_private_endpoint_inventory_excludes_ssm_and_public_egress() -> None:
    text = (ROOT / "infra/modules/network/main.tf").read_text(encoding="utf-8")
    assert "allow_nat_gateway" in text
    assert "private_endpoints_only" in text
    assert "com.amazonaws.${var.aws_region}.ssm" not in text
    assert "ec2messages" not in text
    assert "ssmmessages" not in text


def test_real_plan_normalizer_covers_every_approved_endpoint_policy() -> None:
    expected_interface_endpoints = {
        f'module.network.aws_vpc_endpoint.interface["{name}"]'
        for name in {
            "Bedrock Runtime",
            "CloudWatch Logs",
            "CloudWatch Monitoring",
            "EC2",
            "ECR API",
            "ECR DKR",
            "EKS",
            "EKS Auth",
            "KMS",
            "STS",
            "Secrets Manager",
            "X-Ray",
        }
    }
    assert policy_runner.PLATFORM_INTERFACE_ENDPOINTS == expected_interface_endpoints
    expected_policy_consumers = (
        expected_interface_endpoints | policy_runner.PLATFORM_GATEWAY_ENDPOINTS
    )
    assert set(policy_runner.PLATFORM_ENDPOINT_POLICY_BINDINGS) == expected_policy_consumers
    assert all(
        (address, "policy") in policy_runner.PLATFORM_POLICY_DOCUMENT_BINDINGS
        for address in expected_policy_consumers
    )


def test_endpoint_policy_source_identity_tracks_expiry_update_source() -> None:
    network_path = ROOT / "infra/modules/network/main.tf"
    expected_identity = (
        "infra/modules/network/main.tf",
        sha256(network_path.read_bytes()).hexdigest(),
    )
    endpoint_policy_addresses = {
        policy_address
        for policy_address, _sid in policy_runner.PLATFORM_ENDPOINT_POLICY_BINDINGS.values()
    }
    assert endpoint_policy_addresses
    assert {
        policy_runner.PLATFORM_POLICY_DOCUMENT_SOURCE_SHA256[policy_address]
        for policy_address in endpoint_policy_addresses
    } == {expected_identity}


def test_real_plan_normalizer_protects_eks_trust_and_runtime_policy_sources() -> None:
    eks = (ROOT / "infra/modules/eks/main.tf").read_text(encoding="utf-8")
    assert 'sid     = "ExactEKSClusterServiceTrust"' in eks
    assert 'sid     = "ExactEKSNodeServiceTrust"' in eks
    assert (
        "module.iam.data.aws_iam_policy_document.runtime"
        in policy_runner.SOURCE_PROTECTED_POLICY_DOCUMENTS
    )
    runtime_binding = policy_runner.PLATFORM_POLICY_DOCUMENT_BINDINGS[
        ("module.iam.aws_iam_role_policy.runtime", "policy")
    ]
    assert runtime_binding[2] == frozenset(
        {
            "InvokeExactGlobalInferenceProfile",
            "InvokeExactGlobalInferenceProfileRegionalModel",
            "InvokeExactGlobalInferenceProfileGlobalModel",
            "RuntimeReadPlatformObjects",
            "RuntimeListPlatformBucket",
            "RuntimeUsePlatformKey",
            "RuntimeOpenSearchHealthRead",
            "RuntimeOpenSearchExactIndexQuery",
            "RuntimeWriteSafeApplicationLogs",
            "RuntimeWriteBoundedMetrics",
            "RuntimeWriteXRayTelemetry",
        }
    )
    assert policy_runner.PLATFORM_EKS_CLUSTER_ADDRESS == ("module.eks[0].aws_eks_cluster.this")
    assert policy_runner.PLATFORM_EKS_NODE_GROUP_ADDRESS == (
        "module.eks[0].aws_eks_node_group.application"
    )


def test_runtime_bedrock_policy_uses_three_part_global_inference_contract() -> None:
    iam = (ROOT / "infra/modules/iam/main.tf").read_text(encoding="utf-8")

    assert "foundation_model_id       = trimprefix(" in iam
    assert 'sid       = "InvokeExactGlobalInferenceProfile"' in iam
    assert 'sid       = "InvokeExactGlobalInferenceProfileRegionalModel"' in iam
    assert 'sid       = "InvokeExactGlobalInferenceProfileGlobalModel"' in iam
    assert "resources = [local.inference_profile_arn]" in iam
    assert "resources = [local.regional_model_arn]" in iam
    assert "resources = [local.global_model_arn]" in iam
    assert 'values   = ["unspecified"]' in iam

    profile_statement = iam.split('sid       = "InvokeExactGlobalInferenceProfile"', 1)[1].split(
        "\n  statement {", 1
    )[0]
    assert 'variable = "bedrock:InferenceProfileArn"' not in profile_statement


def test_fis_contract_is_single_target_with_two_stop_alarms() -> None:
    text = (ROOT / "infra/modules/observability/main.tf").read_text(encoding="utf-8")
    fis = text.split('resource "aws_fis_experiment_template" "pod_delete" {', 1)[1]
    assert fis.count("stop_condition {") == 2
    assert 'selection_mode = "COUNT(1)"' in fis
    assert 'selectorType      = "labelSelector"' in fis
    assert 'selectorValue     = "app.kubernetes.io/name=enterprise-ai-api"' in fis
    assert "resource_tags" not in fis
    assert "resource_tag {" not in fis
    assert fis.count("action {") == 1


def test_fis_role_has_exact_eks_pod_delete_discovery_permissions() -> None:
    text = (ROOT / "infra/modules/iam/main.tf").read_text(encoding="utf-8")
    fis = text.split('data "aws_iam_policy_document" "fis" {', 1)[1].split(
        'resource "aws_iam_role_policy" "fis"', 1
    )[0]

    assert 'actions   = ["ec2:DescribeInstances", "ec2:DescribeSubnets", "tag:GetResources"]' in fis
    assert 'actions   = ["eks:DescribeCluster", "eks:AccessKubernetesApi"]' in fis
    assert "resources = [local.eks_cluster_arn]" in fis
    assert "ec2:TerminateInstances" not in fis
    assert "eks:DeleteCluster" not in fis


def test_protected_content_and_non_finite_numbers_are_rejected() -> None:
    with pytest.raises(W6004Error, match="protected"):
        canonical_sha256({"prompt_content": "fixture"})
    with pytest.raises(W6004Error, match="non-finite"):
        canonical_sha256({"amount": float("nan")})
