"""Terraform plan normalization, action classification, and OPA boundaries."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from enum import StrEnum
from pathlib import Path
from typing import cast

from .contracts import ContractError, parse_utc_timestamp
from .lifecycle_io import (
    canonical_json_bytes,
    decode_json_strict,
    ensure_external_path,
    load_json_strict,
    sha256_bytes,
    sha256_file,
)
from .lifecycle_models import PlanAction, PlanActionRecord, PlanSummary
from .process_runner import read_exact_git_blob
from .terraform_runner import CommandRunner, ProcessResult

OPA_VERSION = "1.20.0"
CHECKOV_VERSION = "3.3.16"
TFLINT_VERSION = "0.60.0"
POLICY_IDS = (
    "W5-PLAN-001",
    "W5-REG-001",
    "W5-TAG-001",
    "W5-TAG-002",
    "W5-PLAN-002",
    "W5-S3-001",
    "W5-S3-002",
    "W5-S3-003",
    "W5-S3-004",
    "W5-KMS-001",
    "W5-IAM-001",
    "W5-IAM-002",
    "W5-NET-001",
    "W5-NET-002",
    "W5-OS-001",
    "W5-OS-002",
    "W5-ECR-001",
    "W5-ECR-002",
    "W5-SEC-001",
    "W5-EXC-001",
)
POLICY_CRITICAL_UNKNOWN_KEYS = frozenset(
    {
        "account_id",
        "access_policies",
        "assume_role_policy",
        "aws_region",
        "cidr_block",
        "cloudwatch_log_group_arn",
        "egress",
        "ingress",
        "kms_key_id",
        "kms_key",
        "kms_master_key_id",
        "policy",
        "policy_document",
        "prefix_list_ids",
        "publicly_accessible",
        "security_group_ids",
        "subnet_id",
        "subnet_ids",
        "tags",
        "tags_all",
        "vpc_id",
    }
)
S3_KMS_FIELD_PATH = "rule[].apply_server_side_encryption_by_default[].kms_master_key_id"
OPENSEARCH_DOMAIN_ADDRESS = "module.opensearch.aws_opensearch_domain.this"
OPENSEARCH_ADMIN_ROLE_ADDRESS = "module.iam.aws_iam_role.opensearch_administrator"
OPENSEARCH_ADMIN_ARN_FIELD_PATH = (
    "advanced_security_options[].master_user_options[].master_user_arn"
)
OPENSEARCH_PASSWORD_FIELD_PATH = (
    "advanced_security_options[].master_user_options[].master_user_password"  # noqa: S105 - field
)
OPENSEARCH_USERNAME_FIELD_PATH = (
    "advanced_security_options[].master_user_options[].master_user_name"
)
PLATFORM_VPC_ADDRESS = "module.network.aws_vpc.this"
PLATFORM_KMS_ADDRESS = "module.kms.aws_kms_key.this"
PLATFORM_ECR_ADDRESS = "module.ecr.aws_ecr_repository.this"
W12_PREREQUISITE_ECR_ADDRESSES = frozenset(
    {
        "module.w12_toolchain_ecr.aws_ecr_repository.this",
        "module.w12_codebuild_ecr.aws_ecr_repository.this",
    }
)
PLATFORM_SUBNET_ADDRESSES = (
    "module.network.aws_subnet.private[0]",
    "module.network.aws_subnet.private[1]",
)
PLATFORM_ENDPOINT_SECURITY_GROUP_ADDRESS = "module.network.aws_security_group.endpoints"
PLATFORM_LOG_GROUP_ADDRESSES = {
    "ES_APPLICATION_LOGS": 'module.opensearch.aws_cloudwatch_log_group.this["application"]',
    "AUDIT_LOGS": 'module.opensearch.aws_cloudwatch_log_group.this["audit"]',
    "INDEX_SLOW_LOGS": 'module.opensearch.aws_cloudwatch_log_group.this["index_slow"]',
    "SEARCH_SLOW_LOGS": 'module.opensearch.aws_cloudwatch_log_group.this["search_slow"]',
}
PLATFORM_ECR_REFERENCE_SOURCE_SHA256 = (
    (
        "infra/environments/sandbox/main.tf",
        "8e33057fb1da893f4163588dd70a9f688817d3541ee5c655c7523f0d45cc846f",
    ),
    (
        "infra/modules/ecr/main.tf",
        "a5854aae64686c162d3518f03e3c235dad8e39b6102666ba0c3cde12aceabb19",
    ),
    (
        "infra/modules/kms/outputs.tf",
        "a53438e5dca3c8f0ca4d05651b116ff71927a607a4713ca769d573efabfec3c0",
    ),
)
W12_PREREQUISITE_ECR_REFERENCE_SOURCE_SHA256 = (
    (
        "infra/environments/sandbox/w12_prerequisite_images.tf",
        "",  # W12 requires the reviewed commit/tree context instead of a static digest.
    ),
    PLATFORM_ECR_REFERENCE_SOURCE_SHA256[1],
    PLATFORM_ECR_REFERENCE_SOURCE_SHA256[2],
)
W12_CODEBUILD_NETWORK_SOURCE_SHA256 = (
    (
        "infra/modules/network/main.tf",
        "28cd9e933056fa621e2eb3f6660c1d790f80227d5de3d63b26aa406f94e4a458",
    ),
)
PLATFORM_OPENSEARCH_LOG_SOURCE_SHA256 = (
    (
        "infra/modules/opensearch/main.tf",
        "41b13212d7b4940c8faa0a1ff05690b126e83ad98f4fb26367e3699a1d7563d3",
    ),
)
PLATFORM_GATEWAY_ENDPOINTS = frozenset(
    {
        'module.network.aws_vpc_endpoint.gateway["DynamoDB"]',
        'module.network.aws_vpc_endpoint.gateway["S3"]',
    }
)
PLATFORM_INTERFACE_ENDPOINTS = frozenset(
    {
        'module.network.aws_vpc_endpoint.interface["Bedrock Runtime"]',
        'module.network.aws_vpc_endpoint.interface["CloudWatch Logs"]',
        'module.network.aws_vpc_endpoint.interface["CloudWatch Monitoring"]',
        'module.network.aws_vpc_endpoint.interface["EC2"]',
        'module.network.aws_vpc_endpoint.interface["ECR API"]',
        'module.network.aws_vpc_endpoint.interface["ECR DKR"]',
        'module.network.aws_vpc_endpoint.interface["EKS"]',
        'module.network.aws_vpc_endpoint.interface["EKS Auth"]',
        'module.network.aws_vpc_endpoint.interface["KMS"]',
        'module.network.aws_vpc_endpoint.interface["STS"]',
        'module.network.aws_vpc_endpoint.interface["Secrets Manager"]',
        'module.network.aws_vpc_endpoint.interface["X-Ray"]',
    }
)
PLATFORM_EKS_CLUSTER_ADDRESS = "module.eks[0].aws_eks_cluster.this"
PLATFORM_EKS_NODE_GROUP_ADDRESS = "module.eks[0].aws_eks_node_group.application"
PLATFORM_ALERT_TOPIC_ADDRESS = "module.observability[0].aws_sns_topic.alerts"
PLATFORM_EKS_SOURCE_SHA256 = (
    (
        "infra/modules/eks/main.tf",
        "37b4d6e1a612e029bd9d71d6fc59d042f2f81f57e3e526786f7ef613936a93a4",
    ),
)
PLATFORM_OBSERVABILITY_SOURCE_SHA256 = (
    (
        "infra/modules/observability/main.tf",
        "83737a2a4bc7f4835cfc21c08d290cc4fdc8e1bea7fa8a88fcaeff7e6db4a534",
    ),
)
PLATFORM_ENDPOINT_POLICY_BINDINGS = {
    **{
        f'module.network.aws_vpc_endpoint.gateway["{name}"]': (
            f'module.network.data.aws_iam_policy_document.gateway_endpoint["{name}"]',
            f"ExactSandboxAccount{name.replace(' ', '').replace('-', '')}",
        )
        for name in ("DynamoDB", "S3")
    },
    **{
        f'module.network.aws_vpc_endpoint.interface["{name}"]': (
            f'module.network.data.aws_iam_policy_document.interface_endpoint["{name}"]',
            f"ExactSandboxAccount{name.replace(' ', '').replace('-', '')}",
        )
        for name in (
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
        )
    },
}
PLATFORM_POLICY_DOCUMENT_BINDINGS = {
    ("module.iam.aws_iam_role_policy.ingestion", "policy"): (
        "aws_iam_role_policy",
        "module.iam.data.aws_iam_policy_document.ingestion",
        frozenset(
            {
                "IngestionReadRawObjects",
                "IngestionWriteQuarantineObjects",
                "IngestionWriteProcessedAndEvidenceObjects",
                "IngestionListPlatformBucket",
                "IngestionUsePlatformKey",
                "IngestionOpenSearchDataPlane",
            }
        ),
    ),
    ("module.iam.aws_iam_role_policy.runtime", "policy"): (
        "aws_iam_role_policy",
        "module.iam.data.aws_iam_policy_document.runtime",
        frozenset(
            {
                "InvokeExactGlobalInferenceProfile",
                "InvokeExactGlobalInferenceProfileRegionalModel",
                "InvokeExactGlobalInferenceProfileGlobalModel",
                "RuntimeReadGovernedObjects",
                "RuntimeListGovernedObjects",
                "RuntimeUsePlatformKey",
                "RuntimeOpenSearchHealthRead",
                "RuntimeOpenSearchExactIndexQuery",
                "RuntimeWriteSafeApplicationLogs",
                "RuntimeWriteBoundedMetrics",
                "RuntimeWriteXRayTelemetry",
            }
        ),
    ),
    ("module.iam.aws_iam_role_policy.capstone_build", "policy"): (
        "aws_iam_role_policy",
        "module.iam.data.aws_iam_policy_document.capstone_build",
        frozenset(
            {
                "ReadExactEcrAuthorization",
                "BuildAndInspectExactEcrRepository",
                "InspectExactSourceVersions",
                "RequireSourceBucketVersioning",
                "WriteAndReadExactPrimarySource",
                "EncryptAndReadPrimarySource",
            }
        ),
    ),
    ("module.iam.aws_iam_role_policy.capstone_codebuild", "policy"): (
        "aws_iam_role_policy",
        "module.iam.data.aws_iam_policy_document.capstone_codebuild",
        frozenset(
            {
                "DescribeExactCluster",
                "ReadExactVersionedSource",
                "WriteRedactedBuildResult",
                "VerifyExactRenderResources",
                "VerifyExactInferenceProfile",
                "DecryptExactSource",
                "WriteBoundedLogs",
                "VpcNetworkInterfaceLifecycle",
                "VpcNetworkInterfacePermission",
            }
        ),
    ),
    **{
        (address, "policy"): (
            "aws_iam_role_policy",
            "module.iam.data.aws_iam_policy_document.github_eks_deployment",
            frozenset(
                {
                    "InspectExactVersionedCapstoneInputs",
                    "RequireVersionedCapstoneBucket",
                    "StartOnlyExactCapstoneProject",
                    "WriteVersionedCapstoneSource",
                    "EncryptExactCapstoneSource",
                }
            ),
        )
        for address in (
            "module.iam.aws_iam_role_policy.capstone_deploy_caller",
            "module.iam.aws_iam_role_policy.github_eks_deployment",
        )
    },
    ("module.iam.aws_iam_role_policy.capstone_rollback_reader", "policy"): (
        "aws_iam_role_policy",
        "module.iam.data.aws_iam_policy_document.capstone_rollback_reader",
        frozenset({"ReadExactPriorReleaseVersions", "DecryptPriorReleaseEvidence"}),
    ),
    ("module.kms.aws_kms_key.this", "policy"): (
        "aws_kms_key",
        "module.kms.data.aws_iam_policy_document.this",
        frozenset(
            {
                "EnableExactAccountKeyAdministration",
                "AllowExactWorkloadCryptography",
                "AllowExactOpenSearchLogEncryption",
                "AllowExactBedrockInvocationLogEncryption",
            }
        ),
    ),
    ("module.storage.aws_s3_bucket_policy.tls_only", "policy"): (
        "aws_s3_bucket_policy",
        "module.storage.data.aws_iam_policy_document.tls_only",
        frozenset(
            {
                "DenyNonTLSPlatformAccess",
                "AllowExactBedrockInvocationLogDelivery",
            }
        ),
    ),
    ("module.iam.aws_iam_role.runtime", "assume_role_policy"): (
        "aws_iam_role",
        "module.iam.data.aws_iam_policy_document.runtime_trust",
        frozenset({"ExactPodIdentityRuntimeTrust"}),
    ),
    ("module.iam.aws_iam_role.ingestion", "assume_role_policy"): (
        "aws_iam_role",
        "module.iam.data.aws_iam_policy_document.ingestion_trust",
        frozenset({"ExactPodIdentityIngestionTrust"}),
    ),
    ("module.iam.aws_iam_role.opensearch_administrator", "assume_role_policy"): (
        "aws_iam_role",
        "module.iam.data.aws_iam_policy_document.administrator_trust",
        frozenset({"TimeBoundExactSandboxAdministrator"}),
    ),
    ("module.iam.aws_iam_role.github_oidc", "assume_role_policy"): (
        "aws_iam_role",
        "module.iam.data.aws_iam_policy_document.github_trust",
        frozenset({"ExactGitHubEnvironmentTrust"}),
    ),
    ("module.opensearch.aws_opensearch_domain.this", "access_policies"): (
        "aws_opensearch_domain",
        "module.opensearch.data.aws_iam_policy_document.domain_access",
        frozenset({"ExactSandboxRoleDataPlaneAccess", "RuntimeExactReadAccess"}),
    ),
    (
        "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch",
        "policy_document",
    ): (
        "aws_cloudwatch_log_resource_policy",
        "module.opensearch.data.aws_iam_policy_document.log_delivery",
        frozenset({"ExactOpenSearchLogDelivery"}),
    ),
    ("module.eks.aws_iam_role.cluster", "assume_role_policy"): (
        "aws_iam_role",
        "module.eks[0].data.aws_iam_policy_document.cluster_assume",
        frozenset({"ExactEKSClusterServiceTrust"}),
    ),
    ("module.eks.aws_iam_role.node", "assume_role_policy"): (
        "aws_iam_role",
        "module.eks[0].data.aws_iam_policy_document.node_assume",
        frozenset({"ExactEKSNodeServiceTrust"}),
    ),
    **{
        (address, "policy"): (
            "aws_vpc_endpoint",
            policy_address,
            frozenset({sid}),
        )
        for address, (policy_address, sid) in PLATFORM_ENDPOINT_POLICY_BINDINGS.items()
    },
}
PLATFORM_POLICY_DOCUMENT_EXPRESSION_SHA256 = {
    "module.iam.data.aws_iam_policy_document.runtime_trust": (
        "cf2abf724d5a1a7bd8a77f712b612e1b73ec37190368b46f2e13674d1b54ce60"
    ),
    "module.iam.data.aws_iam_policy_document.ingestion_trust": (
        "c2ff08edcfc1d96c8761f6daa904663618434431a42c90b4402c7cc8054ed2c6"
    ),
    "module.iam.data.aws_iam_policy_document.administrator_trust": (
        "a874adc2ae9cad7c6cb0c96ae31b72daab3bbc9201353040ea353c5024f79faf"
    ),
    "module.iam.data.aws_iam_policy_document.github_trust": (
        "e2bf1ccfa00ecbad7f22434d503acb0a260230d8d7e624e34714fff9c9cb971a"
    ),
    "module.opensearch.data.aws_iam_policy_document.domain_access": (
        "e071ae41f57a734c06db1ffad96459691a622896a86ca879f2b7678557c56c7b"
    ),
    "module.opensearch.data.aws_iam_policy_document.log_delivery": (
        "41adfd97e588ceaec0298ac0be7bbe51ed60f7b2947df3396f828027443e26fa"
    ),
}
PLATFORM_POLICY_DOCUMENT_CALL_EXPRESSION_SHA256 = {
    "module.iam.data.aws_iam_policy_document.runtime_trust": (
        "module.iam",
        "6110cf5a56452fba528472929f44a675dc715806117e060b6b5e5615a364b7ad",
    ),
    "module.iam.data.aws_iam_policy_document.ingestion_trust": (
        "module.iam",
        "6110cf5a56452fba528472929f44a675dc715806117e060b6b5e5615a364b7ad",
    ),
    "module.iam.data.aws_iam_policy_document.administrator_trust": (
        "module.iam",
        "6110cf5a56452fba528472929f44a675dc715806117e060b6b5e5615a364b7ad",
    ),
    "module.iam.data.aws_iam_policy_document.github_trust": (
        "module.iam",
        "6110cf5a56452fba528472929f44a675dc715806117e060b6b5e5615a364b7ad",
    ),
    "module.opensearch.data.aws_iam_policy_document.domain_access": (
        "module.opensearch",
        "eb0c5c05271e2099d02ebe35a665a20db0d718062f1f16ca76734f59b8c31343",
    ),
    "module.opensearch.data.aws_iam_policy_document.log_delivery": (
        "module.opensearch",
        "eb0c5c05271e2099d02ebe35a665a20db0d718062f1f16ca76734f59b8c31343",
    ),
}
PLATFORM_POLICY_DOCUMENT_PLANNED_INPUT_SHA256 = {
    "module.iam.data.aws_iam_policy_document.runtime_trust": frozenset(
        {"eef3619309056cf0700551ff096795a95c10c3daf9773a91faf1df411c4319be"}
    ),
    "module.iam.data.aws_iam_policy_document.ingestion_trust": frozenset(
        {"83a22fd6aad4ff65693b213bf030a9947578f66765d6696864e5cc68ab68f029"}
    ),
    "module.iam.data.aws_iam_policy_document.administrator_trust": frozenset(
        {"fbcbee6e7fc3a4a1b1170ff2d8f63055ab4998b49dc74ad541dc48884ddabaf5"}
    ),
    "module.iam.data.aws_iam_policy_document.github_trust": frozenset(
        {"2ade27d071a7ff7e2cbda4d5e75e61cbaa4554c17215588781384e88e0685fdb"}
    ),
    "module.opensearch.data.aws_iam_policy_document.domain_access": frozenset(
        {
            "5b666964e1082ebf6d3c27c8cb72d8ee230aba5507d3cbb47f804abd84753f02",
            "bfa08d10467373bc1f96fba528a0b1a92e5a29304b3aa414e4d7b03223a7baab",
        }
    ),
    "module.opensearch.data.aws_iam_policy_document.log_delivery": frozenset(
        {"f514b96b02f365165b4070a9e868392c508d5d3c9ed3e2ed0fffdc47225b7410"}
    ),
}
PLATFORM_POLICY_DOCUMENT_SOURCE_SHA256 = {
    "module.iam.data.aws_iam_policy_document.runtime": (
        "infra/bootstrap/modules/platform-iam/main.tf",
        "b16b2b56437c1a7d17ef81d524fd459ad4496b45c5fa04f94b1bc0cf5a79ccfc",
    ),
    "module.iam.data.aws_iam_policy_document.runtime_trust": (
        "infra/bootstrap/modules/platform-iam/main.tf",
        "b16b2b56437c1a7d17ef81d524fd459ad4496b45c5fa04f94b1bc0cf5a79ccfc",
    ),
    "module.iam.data.aws_iam_policy_document.ingestion_trust": (
        "infra/bootstrap/modules/platform-iam/main.tf",
        "b16b2b56437c1a7d17ef81d524fd459ad4496b45c5fa04f94b1bc0cf5a79ccfc",
    ),
    "module.iam.data.aws_iam_policy_document.administrator_trust": (
        "infra/bootstrap/modules/platform-iam/main.tf",
        "b16b2b56437c1a7d17ef81d524fd459ad4496b45c5fa04f94b1bc0cf5a79ccfc",
    ),
    "module.iam.data.aws_iam_policy_document.github_trust": (
        "infra/bootstrap/modules/platform-iam/main.tf",
        "b16b2b56437c1a7d17ef81d524fd459ad4496b45c5fa04f94b1bc0cf5a79ccfc",
    ),
    **{
        f"module.iam.data.aws_iam_policy_document.{name}": (
            "infra/bootstrap/modules/platform-iam/main.tf",
            "b16b2b56437c1a7d17ef81d524fd459ad4496b45c5fa04f94b1bc0cf5a79ccfc",
        )
        for name in (
            "capstone_build",
            "capstone_codebuild",
            "github_eks_deployment",
            "capstone_rollback_reader",
        )
    },
    "module.opensearch.data.aws_iam_policy_document.domain_access": (
        "infra/modules/opensearch/main.tf",
        "41b13212d7b4940c8faa0a1ff05690b126e83ad98f4fb26367e3699a1d7563d3",
    ),
    "module.opensearch.data.aws_iam_policy_document.log_delivery": (
        "infra/modules/opensearch/main.tf",
        "41b13212d7b4940c8faa0a1ff05690b126e83ad98f4fb26367e3699a1d7563d3",
    ),
    "module.eks[0].data.aws_iam_policy_document.cluster_assume": (
        "infra/modules/eks/main.tf",
        "37b4d6e1a612e029bd9d71d6fc59d042f2f81f57e3e526786f7ef613936a93a4",
    ),
    "module.eks[0].data.aws_iam_policy_document.node_assume": (
        "infra/modules/eks/main.tf",
        "37b4d6e1a612e029bd9d71d6fc59d042f2f81f57e3e526786f7ef613936a93a4",
    ),
    **{
        policy_address: (
            "infra/modules/network/main.tf",
            "28cd9e933056fa621e2eb3f6660c1d790f80227d5de3d63b26aa406f94e4a458",
        )
        for policy_address, _sid in PLATFORM_ENDPOINT_POLICY_BINDINGS.values()
    },
}
SOURCE_PROTECTED_POLICY_DOCUMENTS = frozenset(
    {
        "module.iam.data.aws_iam_policy_document.runtime",
        "module.opensearch.data.aws_iam_policy_document.domain_access",
    }
)
_INSTANCE_SELECTOR = re.compile(r"\[[^\]]+\]")
_RESOURCE_REFERENCE = re.compile(r"^(data\.)?(aws_[a-z0-9_]+\.[A-Za-z0-9_-]+)")
SENSITIVE_PLAN_KEYS = frozenset(
    {
        "access_key",
        "api_key",
        "credential",
        "password",
        "private_key",
        "secret",
        "secret_binary",
        "secret_key",
        "secret_string",
        "session_token",
        "token",
    }
)


def _contains_true(value: object) -> bool:
    if value is True:
        return True
    if isinstance(value, dict):
        return any(_contains_true(child) for child in value.values())
    if isinstance(value, list):
        return any(_contains_true(child) for child in value)
    return False


def _valid_sensitivity_shape(value: object) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, dict):
        return all(
            isinstance(key, str) and _valid_sensitivity_shape(child) for key, child in value.items()
        )
    if isinstance(value, list):
        return all(_valid_sensitivity_shape(child) for child in value)
    return False


def _critical_unknown(value: object, key: str | None = None) -> bool:
    if value is True:
        return key in POLICY_CRITICAL_UNKNOWN_KEYS
    if isinstance(value, dict):
        return any(_critical_unknown(child, str(child_key)) for child_key, child in value.items())
    if isinstance(value, list):
        return any(_critical_unknown(child, key) for child in value)
    return False


def _join_address(prefix: str, address: str) -> str:
    return f"{prefix}.{address}" if prefix else address


def _instance_base_address(address: str) -> str:
    return _INSTANCE_SELECTOR.sub("", address)


def _configured_module_index(raw: Mapping[str, object]) -> dict[str, dict[str, object]] | None:
    configuration = raw.get("configuration")
    if not isinstance(configuration, dict):
        return None
    root_module = configuration.get("root_module")
    if not isinstance(root_module, dict):
        return None

    modules: dict[str, dict[str, object]] = {}

    def visit(
        module: dict[str, object],
        prefix: str,
        parent_prefix: str | None,
        call_expressions: object,
    ) -> bool:
        if prefix in modules:
            return False
        modules[prefix] = {
            "module": module,
            "parent_prefix": parent_prefix,
            "call_expressions": call_expressions,
        }
        calls = module.get("module_calls", {})
        if not isinstance(calls, dict):
            return False
        for name, raw_call in calls.items():
            if not isinstance(name, str) or not isinstance(raw_call, dict):
                return False
            child = raw_call.get("module")
            expressions = raw_call.get("expressions", {})
            if not isinstance(child, dict) or not isinstance(expressions, dict):
                return False
            child_prefix = _join_address(prefix, f"module.{name}")
            if not visit(child, child_prefix, prefix, expressions):
                return False
        return True

    if not visit(root_module, "", None, {}):
        return None
    return modules


def _configured_resources(raw: Mapping[str, object]) -> list[dict[str, object]] | None:
    modules = _configured_module_index(raw)
    if modules is None:
        return None
    configured: list[dict[str, object]] = []
    seen: set[str] = set()
    for prefix, entry in modules.items():
        module = entry["module"]
        if not isinstance(module, dict):
            return None
        resources = module.get("resources", [])
        if not isinstance(resources, list):
            return None
        for raw_resource in resources:
            if not isinstance(raw_resource, dict):
                return None
            local_address = raw_resource.get("address")
            if not isinstance(local_address, str):
                return None
            address = _join_address(prefix, local_address)
            if address in seen:
                return None
            seen.add(address)
            resource = dict(raw_resource)
            resource["address"] = address
            resource["_module_prefix"] = prefix
            resource["_local_address"] = local_address
            configured.append(resource)
    return configured


def _configuration_resource(
    raw: Mapping[str, object],
    address: str,
    resource_type: str,
    *,
    mode: str = "managed",
) -> dict[str, object] | None:
    resources = _configured_resources(raw)
    if resources is None:
        return None
    base_address = _instance_base_address(address)
    matches = [
        resource
        for resource in resources
        if resource.get("address") == base_address
        and resource.get("type") == resource_type
        and resource.get("mode") == mode
    ]
    if len(matches) != 1:
        return None
    return matches[0]


def _resource_change(
    raw: Mapping[str, object],
    address: str,
    resource_type: str,
) -> dict[str, object] | None:
    changes = raw.get("resource_changes")
    if not isinstance(changes, list):
        return None
    matches = [
        change
        for change in changes
        if isinstance(change, dict)
        and change.get("address") == address
        and change.get("type") == resource_type
    ]
    if len(matches) != 1:
        return None
    return cast(dict[str, object], matches[0])


def _references_resource(expression: object, address: str) -> bool:
    if not isinstance(expression, dict):
        return False
    references = expression.get("references")
    if not isinstance(references, list):
        return False
    return any(
        isinstance(reference, str) and (reference == address or reference.startswith(f"{address}."))
        for reference in references
    )


def _expression_references(expression: object) -> set[str]:
    references: set[str] = set()
    if isinstance(expression, dict):
        raw_references = expression.get("references", [])
        if isinstance(raw_references, list):
            references.update(
                reference for reference in raw_references if isinstance(reference, str)
            )
        for child in expression.values():
            references.update(_expression_references(child))
    elif isinstance(expression, list):
        for child in expression:
            references.update(_expression_references(child))
    return references


def _direct_reference_expression(expression: object, expected: Sequence[str]) -> bool:
    return (
        isinstance(expression, dict)
        and set(expression) == {"references"}
        and expression.get("references") == list(expected)
    )


_CAPSTONE_SOURCE_SHA256: ContextVar[dict[str, str] | None] = ContextVar(
    "capstone_source_sha256", default=None
)


@contextmanager
def capstone_source_commit(commit: str, tree: str) -> Iterator[None]:
    """Bind W12's policy exceptions to exact reviewed Git blobs, not stale W5 hashes.

    The default W5 path still uses its historical fixed hashes. This scoped W12
    path requires a matching checked-out commit and tree and unchanged files.
    """
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise ContractError("W12 source commit or tree is invalid")
    root = Path(__file__).resolve().parents[2]
    source_names = {
        relative_path
        for group in (
            PLATFORM_ECR_REFERENCE_SOURCE_SHA256,
            W12_PREREQUISITE_ECR_REFERENCE_SOURCE_SHA256,
            W12_CODEBUILD_NETWORK_SOURCE_SHA256,
            PLATFORM_EKS_SOURCE_SHA256,
            PLATFORM_OBSERVABILITY_SOURCE_SHA256,
            PLATFORM_OPENSEARCH_LOG_SOURCE_SHA256,
        )
        for relative_path, _ in group
    }
    source_names.add("infra/modules/iam/main.tf")
    identities: dict[str, str] = {}
    for name in sorted(source_names):
        source = root / name
        if not source.is_file() or source.is_symlink():
            raise ContractError("W12 policy source path is unsafe")
        blob = read_exact_git_blob(root, commit, tree, name)
        if blob != source.read_bytes():
            raise ContractError("W12 policy source differs from approved commit")
        identities[name] = sha256_bytes(blob)
    token = _CAPSTONE_SOURCE_SHA256.set(identities)
    try:
        yield
    finally:
        _CAPSTONE_SOURCE_SHA256.reset(token)


def _source_files_match(identities: Sequence[tuple[str, str]]) -> bool:
    repository_root = Path(__file__).resolve().parents[2]
    capstone = _CAPSTONE_SOURCE_SHA256.get()
    return all(
        (path := repository_root / relative_path).is_file()
        and not path.is_symlink()
        and sha256_bytes(path.read_bytes())
        == (capstone.get(relative_path) if capstone is not None else expected_sha256)
        for relative_path, expected_sha256 in identities
    )


def _resolved_reference_sources(
    raw: Mapping[str, object],
    reference: str,
    module_prefix: str,
    visited: frozenset[tuple[str, str]],
) -> set[str]:
    marker = (module_prefix, reference)
    if marker in visited:
        return set()
    next_visited = visited | {marker}
    modules = _configured_module_index(raw)
    if modules is None or module_prefix not in modules:
        return set()

    resource_match = _RESOURCE_REFERENCE.match(reference)
    if resource_match is not None:
        local_address = f"{resource_match.group(1) or ''}{resource_match.group(2)}"
        return {_join_address(module_prefix, local_address)}

    if reference.startswith("var."):
        variable_name = reference[4:].split(".", 1)[0].split("[", 1)[0]
        module_entry = modules[module_prefix]
        parent_prefix = module_entry.get("parent_prefix")
        call_expressions = module_entry.get("call_expressions")
        if not isinstance(parent_prefix, str) or not isinstance(call_expressions, dict):
            return set()
        expression = call_expressions.get(variable_name)
        return _resolved_expression_sources(raw, expression, parent_prefix, next_visited)

    module_match = re.match(r"^module\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)", reference)
    if module_match is not None:
        child_prefix = _join_address(module_prefix, f"module.{module_match.group(1)}")
        child_entry = modules.get(child_prefix)
        if child_entry is None:
            return set()
        child_module = child_entry.get("module")
        if not isinstance(child_module, dict):
            return set()
        outputs = child_module.get("outputs")
        if not isinstance(outputs, dict):
            return set()
        output = outputs.get(module_match.group(2))
        if not isinstance(output, dict):
            return set()
        return _resolved_expression_sources(
            raw,
            output.get("expression"),
            child_prefix,
            next_visited,
        )

    return set()


def _resolved_expression_sources(
    raw: Mapping[str, object],
    expression: object,
    module_prefix: str,
    visited: frozenset[tuple[str, str]] = frozenset(),
) -> set[str]:
    sources: set[str] = set()
    for reference in _expression_references(expression):
        sources.update(_resolved_reference_sources(raw, reference, module_prefix, visited))
    return sources


def _expressions_at_path(value: object, field_path: str) -> list[object]:
    parts = field_path.split(".")

    def descend(current: object, index: int) -> list[object]:
        if index == len(parts):
            return [current]
        part = parts[index]
        is_collection = part.endswith("[]")
        key = part[:-2] if is_collection else part
        if not isinstance(current, dict) or key not in current:
            return []
        child = current[key]
        if is_collection:
            if not isinstance(child, list):
                return []
            found: list[object] = []
            for item in child:
                found.extend(descend(item, index + 1))
            return found
        return descend(child, index + 1)

    return descend(value, 0)


def _configured_expression_sources(
    raw: Mapping[str, object],
    configuration: Mapping[str, object],
    field_path: str,
) -> set[str] | None:
    expressions = configuration.get("expressions")
    module_prefix = configuration.get("_module_prefix")
    if not isinstance(expressions, dict) or not isinstance(module_prefix, str):
        return None
    matches = _expressions_at_path(expressions, field_path)
    if len(matches) != 1:
        return None
    return _resolved_expression_sources(raw, matches[0], module_prefix)


def _constant_strings_for_key(value: object, expected_key: str) -> set[str]:
    values: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            if key == expected_key and isinstance(child, dict):
                constant = child.get("constant_value")
                if isinstance(constant, str):
                    values.add(constant)
            values.update(_constant_strings_for_key(child, expected_key))
    elif isinstance(value, list):
        for child in value:
            values.update(_constant_strings_for_key(child, expected_key))
    return values


def _critical_unknown_paths(value: object) -> list[str]:
    paths: set[str] = set()

    def visit(current: object, path: str, key: str | None) -> None:
        if current is True:
            if key in POLICY_CRITICAL_UNKNOWN_KEYS:
                paths.add(path)
            return
        if isinstance(current, dict):
            for child_key, child in current.items():
                child_path = f"{path}.{child_key}" if path else str(child_key)
                visit(child, child_path, str(child_key))
        elif isinstance(current, list):
            collection_path = f"{path}[]"
            for child in current:
                visit(child, collection_path, key)

    visit(value, "", None)
    return sorted(paths)


def _remove_unknown_path(
    value: object,
    field_path: str,
    *,
    expected_occurrences: int = 1,
) -> object | None:
    normalized = deepcopy(value)
    parts = field_path.split(".")

    def remove(current: object, index: int) -> int:
        part = parts[index]
        is_collection = part.endswith("[]")
        key = part[:-2] if is_collection else part
        if not isinstance(current, dict) or key not in current:
            return 0
        child = current[key]
        if index == len(parts) - 1:
            if is_collection or child is not True:
                return 0
            del current[key]
            return 1
        if is_collection:
            if not isinstance(child, list):
                return 0
            return sum(remove(item, index + 1) for item in child)
        return remove(child, index + 1)

    if remove(normalized, 0) != expected_occurrences:
        return None
    return normalized


def _source_type(address: str) -> str | None:
    match = re.search(r"(?:^|\.)(aws_[a-z0-9_]+)\.[A-Za-z0-9_-]+(?:\[|$)", address)
    return match.group(1) if match is not None else None


def _managed_sources_exist(raw: Mapping[str, object], addresses: Sequence[str]) -> bool:
    for address in addresses:
        resource_type = _source_type(address)
        if resource_type is None:
            return False
        if _configuration_resource(raw, address, resource_type) is None:
            return False
        if _resource_change(raw, address, resource_type) is None:
            return False
    return True


def _configured_sources_match(
    raw: Mapping[str, object],
    item: Mapping[str, object],
    field_path: str,
    expected_sources: Sequence[str],
) -> bool:
    address = item.get("address")
    resource_type = item.get("type")
    if not isinstance(address, str) or not isinstance(resource_type, str):
        return False
    configuration = _configuration_resource(raw, address, resource_type)
    if configuration is None:
        return False
    actual_sources = _configured_expression_sources(raw, configuration, field_path)
    if actual_sources is None:
        return False
    expected_bases = {_instance_base_address(source) for source in expected_sources}
    return actual_sources == expected_bases and _managed_sources_exist(raw, expected_sources)


def _policy_document_binding(
    raw: Mapping[str, object],
    item: Mapping[str, object],
    field_path: str,
) -> dict[str, object] | None:
    address = item.get("address")
    resource_type = item.get("type")
    if not isinstance(address, str) or not isinstance(resource_type, str):
        return None
    base_address = _instance_base_address(address)
    approved = PLATFORM_POLICY_DOCUMENT_BINDINGS.get(
        (address, field_path)
    ) or PLATFORM_POLICY_DOCUMENT_BINDINGS.get((base_address, field_path))
    if approved is None or resource_type != approved[0]:
        return None
    policy_address = approved[1]
    configuration = _configuration_resource(raw, address, resource_type)
    policy_configuration = _configuration_resource(
        raw,
        policy_address,
        "aws_iam_policy_document",
        mode="data",
    )
    if configuration is None or policy_configuration is None:
        return None
    actual_sources = _configured_expression_sources(raw, configuration, field_path)
    if actual_sources != {_instance_base_address(policy_address)}:
        return None
    consumer_change = _resource_change(raw, address, resource_type)
    if consumer_change is None:
        return None
    consumer_body = consumer_change.get("change")
    if not isinstance(consumer_body, dict):
        return None
    planned_values = consumer_body.get("after")
    planned_fields = _expressions_at_path(planned_values, field_path)
    if len(planned_fields) > 1 or (planned_fields and planned_fields[0] not in (None, "")):
        return None
    policy_expressions = policy_configuration.get("expressions")
    if not isinstance(policy_expressions, dict):
        return None
    statements = policy_expressions.get("statement")
    if not isinstance(statements, list) or len(statements) != len(approved[2]):
        return None
    endpoint_policy_addresses = {
        address for address, _sid in PLATFORM_ENDPOINT_POLICY_BINDINGS.values()
    }
    if policy_address not in endpoint_policy_addresses and _constant_strings_for_key(
        policy_expressions, "sid"
    ) != set(approved[2]):
        return None
    expected_expression_sha256 = PLATFORM_POLICY_DOCUMENT_EXPRESSION_SHA256.get(policy_address)
    if (
        expected_expression_sha256 is not None
        and policy_address not in SOURCE_PROTECTED_POLICY_DOCUMENTS
        and sha256_bytes(canonical_json_bytes(policy_expressions)) != expected_expression_sha256
    ):
        return None
    call_identity = PLATFORM_POLICY_DOCUMENT_CALL_EXPRESSION_SHA256.get(policy_address)
    modules = _configured_module_index(raw)
    if call_identity is not None:
        if modules is None:
            return None
        module_entry = modules.get(call_identity[0])
        if not isinstance(module_entry, dict):
            return None
        call_expressions = module_entry.get("call_expressions")
        if (
            not isinstance(call_expressions, dict)
            or sha256_bytes(canonical_json_bytes(call_expressions)) != call_identity[1]
        ):
            return None
    source_identity = PLATFORM_POLICY_DOCUMENT_SOURCE_SHA256.get(policy_address)
    if source_identity is not None:
        source_path = Path(__file__).resolve().parents[2] / source_identity[0]
        if (
            not source_path.is_file()
            or source_path.is_symlink()
            or sha256_bytes(source_path.read_bytes()) != source_identity[1]
        ):
            return None
    policy_change = _resource_change(raw, policy_address, "aws_iam_policy_document")
    if policy_change is None:
        return None
    policy_body = policy_change.get("change")
    if not isinstance(policy_body, dict):
        return None
    if policy_body.get("actions") != ["read"] or _contains_true(
        policy_body.get("after_sensitive", {})
    ):
        return None
    planned_after = policy_body.get("after")
    expected_planned_input_sha256 = PLATFORM_POLICY_DOCUMENT_PLANNED_INPUT_SHA256.get(
        policy_address
    )
    if (
        expected_planned_input_sha256 is not None
        and policy_address not in SOURCE_PROTECTED_POLICY_DOCUMENTS
    ):
        if not isinstance(planned_after, dict):
            return None
        planned_inputs = {
            key: value
            for key, value in planned_after.items()
            if key not in {"id", "json", "minified_json"}
        }
        if sha256_bytes(canonical_json_bytes(planned_inputs)) not in expected_planned_input_sha256:
            return None
    return {
        "resource_address": address,
        "resource_type": resource_type,
        "field_path": field_path,
        "policy_document_address": policy_address,
        "relationship": "exact-policy-document",
    }


def _provider_computed_unknown(
    raw: Mapping[str, object],
    item: Mapping[str, object],
    body: Mapping[str, object],
    field_path: str,
    bucket_policy_binding: Mapping[str, object] | None,
) -> tuple[dict[str, object], dict[str, object] | None] | None:
    address = item.get("address")
    resource_type = item.get("type")
    if not isinstance(address, str) or not isinstance(resource_type, str):
        return None
    configuration = _configuration_resource(raw, address, resource_type)
    if configuration is None:
        return None
    expressions = configuration.get("expressions")
    if not isinstance(expressions, dict):
        return None

    relationship: str | None = None
    sources: tuple[str, ...] = ()
    if (
        resource_type == "aws_s3_bucket"
        and field_path == "policy"
        and bucket_policy_binding is not None
        and "policy" not in expressions
    ):
        relationship = "separate-tls-bucket-policy"
    elif address in PLATFORM_GATEWAY_ENDPOINTS:
        after = body.get("after")
        if not isinstance(after, dict) or after.get("vpc_endpoint_type") != "Gateway":
            return None
        if field_path in {"policy", "security_group_ids", "subnet_ids"}:
            field_name = field_path.split(".")[-1]
            if field_name in expressions:
                return None
            relationship = "gateway-endpoint-provider-default"
    elif address in PLATFORM_INTERFACE_ENDPOINTS and field_path == "policy":
        after = body.get("after")
        if (
            not isinstance(after, dict)
            or after.get("vpc_endpoint_type") != "Interface"
            or "policy" in expressions
        ):
            return None
        relationship = "interface-endpoint-provider-default-policy"
    elif address == PLATFORM_EKS_CLUSTER_ADDRESS and field_path == "vpc_config[].vpc_id":
        if not _source_files_match(PLATFORM_EKS_SOURCE_SHA256):
            return None
        subnet_sources = _configured_expression_sources(
            raw, configuration, "vpc_config[].subnet_ids"
        )
        if subnet_sources != {_instance_base_address(PLATFORM_SUBNET_ADDRESSES[0])}:
            return None
        sources = (PLATFORM_VPC_ADDRESS, *PLATFORM_SUBNET_ADDRESSES)
        if not _managed_sources_exist(raw, sources):
            return None
        relationship = "eks-vpc-derived-from-private-subnets"
    elif address == PLATFORM_ALERT_TOPIC_ADDRESS and field_path == "policy":
        after = body.get("after")
        if (
            not _source_files_match(PLATFORM_OBSERVABILITY_SOURCE_SHA256)
            or not isinstance(after, dict)
            or after.get("name") != "enterprise-ai-sandbox-alerts"
            or after.get("kms_master_key_id") != "alias/aws/sns"
            or "policy" in expressions
        ):
            return None
        relationship = "sns-provider-default-policy"
    elif (
        address == "module.opensearch.aws_opensearch_domain.this"
        and field_path == "vpc_options[].vpc_id"
    ):
        subnet_sources = _configured_expression_sources(
            raw, configuration, "vpc_options[].subnet_ids"
        )
        security_group_sources = _configured_expression_sources(
            raw, configuration, "vpc_options[].security_group_ids"
        )
        if subnet_sources != {_instance_base_address(PLATFORM_SUBNET_ADDRESSES[0])}:
            return None
        if security_group_sources != {PLATFORM_ENDPOINT_SECURITY_GROUP_ADDRESS}:
            return None
        sources = (
            PLATFORM_VPC_ADDRESS,
            PLATFORM_SUBNET_ADDRESSES[0],
            PLATFORM_ENDPOINT_SECURITY_GROUP_ADDRESS,
        )
        if not _managed_sources_exist(raw, sources):
            return None
        relationship = "opensearch-vpc-derived-from-network"

    if relationship is None:
        return None
    provider_record: dict[str, object] = {
        "address": address,
        "type": resource_type,
        "unknown_paths": [field_path],
    }
    reference_record: dict[str, object] | None = None
    if sources:
        reference_record = {
            "address": address,
            "type": resource_type,
            "unknown_paths": [field_path],
            "source_addresses": sorted(sources),
            "relationship": relationship,
        }
    return provider_record, reference_record


def _resource_reference_binding(
    raw: Mapping[str, object],
    item: Mapping[str, object],
    field_path: str,
) -> dict[str, object] | None:
    address = item.get("address")
    resource_type = item.get("type")
    if not isinstance(address, str) or not isinstance(resource_type, str):
        return None

    sources: tuple[str, ...] | None = None
    relationship: str | None = None
    vpc_consumers = {
        "module.network.aws_default_security_group.restricted",
        "module.network.aws_route_table.private",
        "module.network.aws_security_group.endpoints",
        "module.network.aws_security_group.capstone_codebuild",
        *PLATFORM_GATEWAY_ENDPOINTS,
        *PLATFORM_INTERFACE_ENDPOINTS,
    }
    if address in vpc_consumers and field_path == "vpc_id":
        sources = (PLATFORM_VPC_ADDRESS,)
        relationship = "network-vpc-reference"
    elif address in PLATFORM_SUBNET_ADDRESSES and field_path == "vpc_id":
        sources = (PLATFORM_VPC_ADDRESS,)
        relationship = "network-vpc-reference"
    elif (
        address.startswith("module.network.aws_route_table_association.private[")
        and field_path == "subnet_id"
    ):
        suffix = address.removeprefix("module.network.aws_route_table_association.private")
        candidate = f"module.network.aws_subnet.private{suffix}"
        if candidate not in PLATFORM_SUBNET_ADDRESSES:
            return None
        sources = (candidate,)
        relationship = "network-subnet-reference"
    elif address in PLATFORM_INTERFACE_ENDPOINTS and field_path == "subnet_ids":
        sources = PLATFORM_SUBNET_ADDRESSES
        relationship = "network-private-subnets-reference"
    elif address in PLATFORM_INTERFACE_ENDPOINTS and field_path == "security_group_ids":
        sources = (PLATFORM_ENDPOINT_SECURITY_GROUP_ADDRESS,)
        relationship = "network-endpoint-security-group-reference"
    elif (
        address == "module.network.aws_security_group.capstone_codebuild"
        and resource_type == "aws_security_group"
        and field_path == "egress[].prefix_list_ids"
        and _source_files_match(W12_CODEBUILD_NETWORK_SOURCE_SHA256)
    ):
        sources = ('module.network.aws_vpc_endpoint.gateway["S3"]',)
        relationship = "network-s3-gateway-prefix-list-reference"
    elif address == PLATFORM_EKS_CLUSTER_ADDRESS:
        if field_path == "encryption_config[].provider[].key_arn":
            sources = (PLATFORM_KMS_ADDRESS,)
            relationship = "platform-kms-key-reference"
        elif field_path == "vpc_config[].subnet_ids":
            sources = PLATFORM_SUBNET_ADDRESSES
            relationship = "network-private-subnets-reference"
    elif address == PLATFORM_EKS_NODE_GROUP_ADDRESS and field_path == "subnet_ids":
        sources = PLATFORM_SUBNET_ADDRESSES
        relationship = "network-private-subnets-reference"
    elif (
        address.startswith("module.opensearch.aws_cloudwatch_log_group.this[")
        and field_path == "kms_key_id"
    ):
        sources = (PLATFORM_KMS_ADDRESS,)
        relationship = "platform-kms-key-reference"
    elif (
        address in ({PLATFORM_ECR_ADDRESS} | W12_PREREQUISITE_ECR_ADDRESSES)
        and resource_type == "aws_ecr_repository"
        and field_path == "encryption_configuration[].kms_key"
        and _ecr_kms_unknown_is_exact(raw, item, address)
    ):
        sources = (PLATFORM_KMS_ADDRESS,)
        relationship = "platform-ecr-kms-key-reference"
    elif address == "module.opensearch.aws_opensearch_domain.this":
        if field_path == "encrypt_at_rest[].kms_key_id":
            sources = (PLATFORM_KMS_ADDRESS,)
            relationship = "platform-kms-key-reference"
        elif field_path == "vpc_options[].subnet_ids":
            sources = (PLATFORM_SUBNET_ADDRESSES[0],)
            relationship = "network-subnet-reference"
        elif field_path == "vpc_options[].security_group_ids":
            sources = (PLATFORM_ENDPOINT_SECURITY_GROUP_ADDRESS,)
            relationship = "network-endpoint-security-group-reference"
        elif (
            field_path == "log_publishing_options[].cloudwatch_log_group_arn"
            and _opensearch_log_unknowns_are_exact(raw, item)
        ):
            sources = tuple(sorted(PLATFORM_LOG_GROUP_ADDRESSES.values()))
            relationship = "opensearch-log-groups-reference"
    elif (
        address == "module.storage.aws_s3_bucket_server_side_encryption_configuration.this"
        and field_path == S3_KMS_FIELD_PATH
    ):
        sources = (PLATFORM_KMS_ADDRESS,)
        relationship = "platform-kms-key-reference"

    if sources is None or relationship is None:
        return None
    if address in {PLATFORM_EKS_CLUSTER_ADDRESS, PLATFORM_EKS_NODE_GROUP_ADDRESS} and not (
        _source_files_match(PLATFORM_EKS_SOURCE_SHA256)
    ):
        return None
    if relationship == "opensearch-log-groups-reference":
        sources_match = True
    elif relationship == "network-s3-gateway-prefix-list-reference":
        configuration = _configuration_resource(raw, address, resource_type)
        expressions = configuration.get("expressions") if configuration else None
        matches = (
            _expressions_at_path(expressions, field_path) if isinstance(expressions, dict) else []
        )
        egress = expressions.get("egress") if isinstance(expressions, dict) else None
        s3_prefix_list_reference = 'aws_vpc_endpoint.gateway["S3"].prefix_list_id'
        if isinstance(egress, dict):
            references = egress.get("references")
            expression_matches = (
                set(egress) == {"references"}
                and isinstance(references, list)
                and len(references) == 4
                and all(isinstance(reference, str) for reference in references)
                and set(references)
                == {
                    "var.vpc_cidr",
                    s3_prefix_list_reference,
                    'aws_vpc_endpoint.gateway["S3"]',
                    "aws_vpc_endpoint.gateway",
                }
            )
        else:
            expression_matches = (
                isinstance(egress, list)
                and len(egress) == 2
                and len(matches) == 1
                and _expression_references(matches[0])
                in (
                    {s3_prefix_list_reference},
                    {
                        s3_prefix_list_reference,
                        'aws_vpc_endpoint.gateway["S3"]',
                    },
                )
            )
        sources_match = (
            expression_matches
            and _resolved_expression_sources(
                raw, {"references": [s3_prefix_list_reference]}, "module.network"
            )
            == {"module.network.aws_vpc_endpoint.gateway"}
            and _managed_sources_exist(raw, sources)
        )
    else:
        sources_match = _configured_sources_match(raw, item, field_path, sources)
    provider_arn_relationship = relationship in {
        "platform-ecr-kms-key-reference",
        "opensearch-log-groups-reference",
    }
    if not sources_match or (
        provider_arn_relationship
        and not all(_source_arn_is_provider_computed(raw, source) for source in sources)
    ):
        return None
    return {
        "address": address,
        "type": resource_type,
        "unknown_paths": [field_path],
        "source_addresses": sorted(sources),
        "relationship": relationship,
    }


def _source_arn_is_provider_computed(raw: Mapping[str, object], address: str) -> bool:
    resource_type = _source_type(address)
    if resource_type is None or _configuration_resource(raw, address, resource_type) is None:
        return False
    source = _resource_change(raw, address, resource_type)
    if source is None:
        return False
    body = source.get("change")
    if not isinstance(body, dict) or body.get("actions") != ["create"]:
        return False
    after = body.get("after")
    after_unknown = body.get("after_unknown")
    return (
        isinstance(after, dict)
        and after.get("arn") is None
        and isinstance(after_unknown, dict)
        and after_unknown.get("arn") is True
        and not _contains_true(body.get("after_sensitive", {}))
    )


def _ecr_kms_unknown_is_exact(
    raw: Mapping[str, object], item: Mapping[str, object], address: str
) -> bool:
    modules = _configured_module_index(raw)
    configuration = _configuration_resource(raw, address, "aws_ecr_repository")
    source_identities = (
        PLATFORM_ECR_REFERENCE_SOURCE_SHA256
        if address == PLATFORM_ECR_ADDRESS
        else W12_PREREQUISITE_ECR_REFERENCE_SOURCE_SHA256
    )
    body = item.get("change")
    if (
        modules is None
        or configuration is None
        or not isinstance(body, dict)
        or (address in W12_PREREQUISITE_ECR_ADDRESSES and _CAPSTONE_SOURCE_SHA256.get() is None)
        or not _source_files_match(source_identities)
    ):
        return False
    expressions = configuration.get("expressions")
    local_matches = (
        _expressions_at_path(expressions, "encryption_configuration[].kms_key")
        if isinstance(expressions, dict)
        else []
    )
    ecr_module = modules.get(address.removesuffix(".aws_ecr_repository.this"))
    kms_module = modules.get("module.kms")
    if not isinstance(ecr_module, dict) or not isinstance(kms_module, dict):
        return False
    call_expressions = ecr_module.get("call_expressions")
    kms_configuration = kms_module.get("module")
    outputs = kms_configuration.get("outputs") if isinstance(kms_configuration, dict) else None
    key_arn_output = outputs.get("key_arn") if isinstance(outputs, dict) else None
    if (
        len(local_matches) != 1
        or not _direct_reference_expression(local_matches[0], ("var.kms_key_arn",))
        or not isinstance(call_expressions, dict)
        or not _direct_reference_expression(
            call_expressions.get("kms_key_arn"),
            ("module.kms.key_arn", "module.kms"),
        )
        or not isinstance(key_arn_output, dict)
        or not _direct_reference_expression(
            key_arn_output.get("expression"),
            ("aws_kms_key.this.arn", "aws_kms_key.this"),
        )
    ):
        return False
    after = _single_nested_block(body.get("after"), "encryption_configuration")
    unknown = _single_nested_block(body.get("after_unknown"), "encryption_configuration")
    sensitive = _single_nested_block(body.get("after_sensitive"), "encryption_configuration")
    return (
        after is not None
        and set(after) <= {"encryption_type", "kms_key"}
        and after.get("encryption_type") == "KMS"
        and after.get("kms_key") is None
        and unknown == {"kms_key": True}
        and sensitive == {}
    )


def _opensearch_log_unknowns_are_exact(
    raw: Mapping[str, object], item: Mapping[str, object]
) -> bool:
    configuration = _configuration_resource(raw, OPENSEARCH_DOMAIN_ADDRESS, "aws_opensearch_domain")
    body = item.get("change")
    if (
        configuration is None
        or not isinstance(body, dict)
        or not _source_files_match(PLATFORM_OPENSEARCH_LOG_SOURCE_SHA256)
    ):
        return False
    expressions = configuration.get("expressions")
    module_prefix = configuration.get("_module_prefix")
    if not isinstance(expressions, dict) or module_prefix != "module.opensearch":
        return False
    configured_logs = expressions.get("log_publishing_options")
    after_logs = (
        body.get("after", {}).get("log_publishing_options")
        if isinstance(body.get("after"), dict)
        else None
    )
    unknown_logs = (
        body.get("after_unknown", {}).get("log_publishing_options")
        if isinstance(body.get("after_unknown"), dict)
        else None
    )
    sensitive_logs = (
        body.get("after_sensitive", {}).get("log_publishing_options")
        if isinstance(body.get("after_sensitive"), dict)
        else None
    )
    if not all(
        isinstance(value, list) and len(value) == 4
        for value in (configured_logs, after_logs, unknown_logs, sensitive_logs)
    ):
        return False
    seen: set[str] = set()
    for configured in cast(list[object], configured_logs):
        if not isinstance(configured, dict):
            return False
        log_type_expression = configured.get("log_type")
        arn_expression = configured.get("cloudwatch_log_group_arn")
        if not isinstance(log_type_expression, dict):
            return False
        log_type = log_type_expression.get("constant_value")
        if not isinstance(log_type, str) or log_type not in PLATFORM_LOG_GROUP_ADDRESSES:
            return False
        local_source = PLATFORM_LOG_GROUP_ADDRESSES[log_type].removeprefix("module.opensearch.")
        if not _direct_reference_expression(
            arn_expression,
            (f"{local_source}.arn", local_source, "aws_cloudwatch_log_group.this"),
        ):
            return False
        seen.add(log_type)
    if seen != set(PLATFORM_LOG_GROUP_ADDRESSES):
        return False
    for planned in cast(list[object], after_logs):
        if (
            not isinstance(planned, dict)
            or set(planned) - {"enabled", "log_type", "cloudwatch_log_group_arn"}
            or planned.get("enabled") is not True
            or planned.get("log_type") not in PLATFORM_LOG_GROUP_ADDRESSES
            or planned.get("cloudwatch_log_group_arn") is not None
        ):
            return False
    return all(
        unknown == {"cloudwatch_log_group_arn": True}
        for unknown in cast(list[object], unknown_logs)
    ) and all(sensitive == {} for sensitive in cast(list[object], sensitive_logs))


def _single_referenced_managed_resource(
    raw: Mapping[str, object],
    expression: object,
    resource_type: str,
) -> str | None:
    resources = _configured_resources(raw)
    if resources is None:
        return None
    addresses = [
        cast(str, resource["address"])
        for resource in resources
        if resource.get("type") == resource_type
        and resource.get("mode") == "managed"
        and isinstance(resource.get("address"), str)
        and _references_resource(expression, cast(str, resource["address"]))
    ]
    if len(addresses) != 1:
        return None
    return addresses[0]


def _named_expressions(value: object, name: str) -> list[object]:
    matches: list[object] = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == name:
                matches.append(child)
            matches.extend(_named_expressions(child, name))
    elif isinstance(value, list):
        for child in value:
            matches.extend(_named_expressions(child, name))
    return matches


def _s3_tls_policy_text_valid(policy: str) -> bool:
    normalized = policy.casefold()
    return (
        '"effect":"deny"' in normalized
        and "aws:securetransport" in normalized
        and '"false"' in normalized
    )


def _companion_bucket_policy_address(raw: Mapping[str, object], bucket_address: str) -> str | None:
    resources = _configured_resources(raw)
    if resources is None:
        return None

    configured_policies: list[str] = []
    for resource in resources:
        if (
            not isinstance(resource, dict)
            or resource.get("type") != "aws_s3_bucket_policy"
            or resource.get("mode") != "managed"
            or not isinstance(resource.get("address"), str)
        ):
            continue
        expressions = resource.get("expressions")
        if not isinstance(expressions, dict) or "policy" not in expressions:
            continue
        sources = _configured_expression_sources(raw, resource, "bucket")
        if sources == {_instance_base_address(bucket_address)}:
            configured_policies.append(cast(str, resource["address"]))

    if len(configured_policies) != 1:
        return None
    companion_address = configured_policies[0]
    matching_change = _resource_change(raw, companion_address, "aws_s3_bucket_policy")
    if matching_change is None:
        return None
    companion_change = matching_change.get("change")
    if not isinstance(companion_change, dict):
        return None
    after = companion_change.get("after")
    known_tls_policy = (
        isinstance(after, dict)
        and isinstance(after.get("policy"), str)
        and bool(after["policy"])
        and _s3_tls_policy_text_valid(cast(str, after["policy"]))
        and not _critical_unknown(companion_change.get("after_unknown", {}))
    )
    structural_tls_policy = _policy_document_binding(raw, matching_change, "policy") is not None
    if not (known_tls_policy or structural_tls_policy) or _contains_true(
        companion_change.get("after_sensitive", {})
    ):
        return None
    return companion_address


def _bucket_policy_binding(
    raw: Mapping[str, object],
    item: Mapping[str, object],
) -> dict[str, object] | None:
    address = item.get("address")
    if not isinstance(address, str) or item.get("type") != "aws_s3_bucket":
        return None
    configuration = _configuration_resource(raw, address, "aws_s3_bucket")
    if configuration is None:
        return None
    expressions = configuration.get("expressions")
    if not isinstance(expressions, dict) or "policy" in expressions:
        return None
    policy_address = _companion_bucket_policy_address(raw, address)
    if policy_address is None:
        return None
    return {"bucket_address": address, "policy_address": policy_address}


def _single_nested_block(value: object, key: str) -> dict[str, object] | None:
    if not isinstance(value, dict):
        return None
    blocks = value.get(key)
    if not isinstance(blocks, list) or len(blocks) != 1 or not isinstance(blocks[0], dict):
        return None
    return cast(dict[str, object], blocks[0])


def _opensearch_admin_role_chain_is_exact(
    raw: Mapping[str, object],
    configuration: Mapping[str, object],
) -> bool:
    modules = _configured_module_index(raw)
    expressions = configuration.get("expressions")
    if modules is None or not isinstance(expressions, dict):
        return False
    arn_expressions = _expressions_at_path(expressions, OPENSEARCH_ADMIN_ARN_FIELD_PATH)
    if len(arn_expressions) != 1 or _expression_references(arn_expressions[0]) != {
        "var.administrator_role_arn"
    }:
        return False

    opensearch_entry = modules.get("module.opensearch")
    iam_entry = modules.get("module.iam")
    if opensearch_entry is None or iam_entry is None:
        return False
    if opensearch_entry.get("parent_prefix") != "" or iam_entry.get("parent_prefix") != "":
        return False
    opensearch_arguments = opensearch_entry.get("call_expressions")
    if not isinstance(opensearch_arguments, dict):
        return False
    if _expression_references(opensearch_arguments.get("administrator_role_arn")) != {
        "module.iam",
        "module.iam.opensearch_administrator_role_arn",
    }:
        return False

    iam_module = iam_entry.get("module")
    if not isinstance(iam_module, dict):
        return False
    outputs = iam_module.get("outputs")
    if not isinstance(outputs, dict):
        return False
    output = outputs.get("opensearch_administrator_role_arn")
    if not isinstance(output, dict):
        return False
    return _expression_references(output.get("expression")) == {
        "aws_iam_role.opensearch_administrator",
        "aws_iam_role.opensearch_administrator.arn",
    }


def _expiry_tag_reconciliation(before: object, after: object) -> str | None:
    if not isinstance(before, dict) or not isinstance(after, dict) or set(before) != set(after):
        return None
    if {key: value for key, value in before.items() if key != "ExpiresAt"} != {
        key: value for key, value in after.items() if key != "ExpiresAt"
    }:
        return None
    previous = before.get("ExpiresAt")
    current = after.get("ExpiresAt")
    if not isinstance(previous, str) or not isinstance(current, str) or previous == current:
        return None
    try:
        parse_utc_timestamp(previous, "previous ExpiresAt")
        parse_utc_timestamp(current, "current ExpiresAt")
    except ContractError:
        return None
    return current


def _admin_trust_expiry_reconciliation(
    before: object,
    after: object,
    *,
    previous_expiry: str,
    current_expiry: str,
) -> bool:
    """Accept only a bounded extension of the administrator trust deadline."""
    normalized: list[object] = []
    trust_expiries: list[str] = []
    for document in (before, after):
        candidate = deepcopy(document)
        if not isinstance(candidate, dict):
            return False
        statements = candidate.get("Statement")
        if not isinstance(statements, list) or len(statements) != 1:
            return False
        statement = statements[0]
        if (
            not isinstance(statement, dict)
            or statement.get("Sid") != "TimeBoundExactSandboxAdministrator"
        ):
            return False
        condition = statement.get("Condition")
        date_less_than = condition.get("DateLessThan") if isinstance(condition, dict) else None
        trust_expiry = (
            date_less_than.get("aws:CurrentTime") if isinstance(date_less_than, dict) else None
        )
        if not isinstance(trust_expiry, str):
            return False
        trust_expiries.append(trust_expiry)
        cast(dict[str, object], date_less_than)["aws:CurrentTime"] = "OWNER_APPROVED_EXPIRY"
        normalized.append(candidate)
    try:
        previous_trust_expiry = parse_utc_timestamp(
            trust_expiries[0], "previous administrator trust expiry"
        )
        current_trust_expiry = parse_utc_timestamp(
            trust_expiries[1], "current administrator trust expiry"
        )
        previous_resource_expiry = parse_utc_timestamp(previous_expiry, "previous resource expiry")
        current_resource_expiry = parse_utc_timestamp(current_expiry, "current resource expiry")
    except ContractError:
        return False
    return (
        previous_trust_expiry <= previous_resource_expiry
        and previous_resource_expiry < current_resource_expiry
        and previous_trust_expiry < current_trust_expiry <= current_resource_expiry
        and normalized[0] == normalized[1]
    )


def _existing_opensearch_admin_role_is_exact(
    role_body: Mapping[str, object],
    master_user_arn: str,
) -> bool:
    before = role_body.get("before")
    after = role_body.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        return False
    if _contains_true(role_body.get("after_unknown", {})) or _contains_true(
        role_body.get("after_sensitive", {})
    ):
        return False
    if (
        before.get("arn") != master_user_arn
        or after.get("arn") != master_user_arn
        or not isinstance(master_user_arn, str)
        or not master_user_arn
    ):
        return False
    before_policy = before.get("assume_role_policy")
    after_policy = after.get("assume_role_policy")
    if not isinstance(before_policy, str) or not isinstance(after_policy, str):
        return False
    try:
        canonical_before = policy_semantic_value(before_policy)
        canonical_after = policy_semantic_value(after_policy)
    except ContractError:
        return False
    actions = role_body.get("actions")
    if actions == ["no-op"]:
        return canonical_before == canonical_after and before == after
    if actions != ["update"]:
        return False
    tags_expiry = _expiry_tag_reconciliation(before.get("tags"), after.get("tags"))
    tags_all_expiry = _expiry_tag_reconciliation(
        before.get("tags_all"),
        after.get("tags_all"),
    )
    previous_expiry = cast(dict[str, object], before.get("tags", {})).get("ExpiresAt")
    if (
        not isinstance(previous_expiry, str)
        or tags_expiry is None
        or tags_expiry != tags_all_expiry
        or (
            canonical_before != canonical_after
            and not _admin_trust_expiry_reconciliation(
                canonical_before,
                canonical_after,
                previous_expiry=previous_expiry,
                current_expiry=tags_expiry,
            )
        )
    ):
        return False
    before = {**before, "assume_role_policy": canonical_after}
    after = {**after, "assume_role_policy": canonical_after}
    return {key: value for key, value in before.items() if key not in {"tags", "tags_all"}} == {
        key: value for key, value in after.items() if key not in {"tags", "tags_all"}
    }


def _opensearch_omitted_password_sensitivity(
    raw: Mapping[str, object],
    item: Mapping[str, object],
    body: Mapping[str, object],
) -> tuple[object, object, dict[str, object]] | None:
    """Normalize only the provider marker for an omitted OpenSearch password."""
    if (
        item.get("address") != OPENSEARCH_DOMAIN_ADDRESS
        or item.get("type") != "aws_opensearch_domain"
        or body.get("actions") not in (["create"], ["no-op"], ["update"])
        or (body.get("actions") == ["create"] and body.get("before") is not None)
    ):
        return None

    after = body.get("after")
    advanced = _single_nested_block(after, "advanced_security_options")
    master = _single_nested_block(advanced, "master_user_options")
    if advanced is None or master is None:
        return None
    if (
        advanced.get("enabled") is not True
        or advanced.get("internal_user_database_enabled") is not False
    ):
        return None
    if master.get("master_user_name") not in (None, "") or master.get(
        "master_user_password"
    ) not in (
        None,
        "",
    ):
        return None

    after_unknown = body.get("after_unknown", {})
    arn_unknowns = _expressions_at_path(after_unknown, OPENSEARCH_ADMIN_ARN_FIELD_PATH)
    password_unknowns = _expressions_at_path(after_unknown, OPENSEARCH_PASSWORD_FIELD_PATH)
    if any(_contains_true(value) for value in password_unknowns):
        return None

    configuration = _configuration_resource(raw, OPENSEARCH_DOMAIN_ADDRESS, "aws_opensearch_domain")
    if configuration is None:
        return None
    expressions = configuration.get("expressions")
    if not isinstance(expressions, dict):
        return None
    if _expressions_at_path(expressions, OPENSEARCH_PASSWORD_FIELD_PATH):
        return None
    if _expressions_at_path(expressions, OPENSEARCH_USERNAME_FIELD_PATH):
        return None
    sources = _configured_expression_sources(raw, configuration, OPENSEARCH_ADMIN_ARN_FIELD_PATH)
    if sources != {OPENSEARCH_ADMIN_ROLE_ADDRESS} or not _opensearch_admin_role_chain_is_exact(
        raw, configuration
    ):
        return None

    role_configuration = _configuration_resource(
        raw,
        OPENSEARCH_ADMIN_ROLE_ADDRESS,
        "aws_iam_role",
    )
    role_change = _resource_change(raw, OPENSEARCH_ADMIN_ROLE_ADDRESS, "aws_iam_role")
    if role_configuration is None or role_change is None:
        return None
    role_body = role_change.get("change")
    if not isinstance(role_body, dict):
        return None

    master_user_arn = master.get("master_user_arn")
    if master_user_arn is None:
        if (
            arn_unknowns != [True]
            or role_body.get("actions") != ["create"]
            or role_body.get("before") is not None
            or _expressions_at_path(role_body.get("after_unknown", {}), "arn") != [True]
            or _contains_true(role_body.get("after_sensitive", {}))
        ):
            return None
        relationship = "omitted-null-password-with-structurally-resolved-admin-role"
    elif isinstance(master_user_arn, str) and master_user_arn:
        if any(_contains_true(value) for value in arn_unknowns) or not (
            _existing_opensearch_admin_role_is_exact(role_body, master_user_arn)
        ):
            return None
        relationship = "omitted-null-password-with-existing-admin-role"
    else:
        return None

    normalized = _remove_unknown_path(
        body.get("after_sensitive", {}),
        OPENSEARCH_PASSWORD_FIELD_PATH,
    )
    if normalized is None or _contains_true(normalized):
        return None
    normalized_after = deepcopy(after)
    normalized_advanced = _single_nested_block(normalized_after, "advanced_security_options")
    normalized_master = _single_nested_block(normalized_advanced, "master_user_options")
    if normalized_master is None:
        return None
    normalized_master.pop("master_user_password", None)
    return (
        normalized_after,
        normalized,
        {
            "address": OPENSEARCH_DOMAIN_ADDRESS,
            "type": "aws_opensearch_domain",
            "field_path": OPENSEARCH_PASSWORD_FIELD_PATH,
            "relationship": relationship,
            "source_address": OPENSEARCH_ADMIN_ROLE_ADDRESS,
        },
    )


def _s3_kms_encryption_binding(
    raw: Mapping[str, object],
    item: Mapping[str, object],
    body: Mapping[str, object],
) -> dict[str, object] | None:
    encryption_address = item.get("address")
    resource_type = "aws_s3_bucket_server_side_encryption_configuration"
    if not isinstance(encryption_address, str) or item.get("type") != resource_type:
        return None
    configuration = _configuration_resource(raw, encryption_address, resource_type)
    if configuration is None:
        return None
    expressions = configuration.get("expressions")
    if not isinstance(expressions, dict):
        return None

    bucket_sources = _configured_expression_sources(raw, configuration, "bucket")
    kms_sources = _configured_expression_sources(raw, configuration, S3_KMS_FIELD_PATH)
    if bucket_sources is None or len(bucket_sources) != 1:
        return None
    bucket_address = next(iter(bucket_sources))
    if kms_sources is None or len(kms_sources) != 1:
        return None
    kms_key_address = next(iter(kms_sources))

    after = body.get("after")
    rule = _single_nested_block(after, "rule")
    defaults = _single_nested_block(rule, "apply_server_side_encryption_by_default")
    if defaults is None or defaults.get("sse_algorithm") != "aws:kms":
        return None

    bucket_change = _resource_change(raw, bucket_address, "aws_s3_bucket")
    kms_change = _resource_change(raw, kms_key_address, "aws_kms_key")
    if bucket_change is None or kms_change is None:
        return None
    kms_body = kms_change.get("change")
    if not isinstance(kms_body, dict):
        return None
    kms_after = kms_body.get("after")
    known_kms_policy = (
        isinstance(kms_after, dict)
        and isinstance(kms_after.get("policy"), str)
        and bool(kms_after["policy"])
    )
    structural_kms_policy = _policy_document_binding(raw, kms_change, "policy") is not None
    if not (known_kms_policy or structural_kms_policy) or _contains_true(
        kms_body.get("after_sensitive", {})
    ):
        return None
    bucket_body = bucket_change.get("change")
    if not isinstance(bucket_body, dict) or _contains_true(bucket_body.get("after_sensitive", {})):
        return None

    return {
        "bucket_address": bucket_address,
        "encryption_address": encryption_address,
        "kms_key_address": kms_key_address,
        "field_path": S3_KMS_FIELD_PATH,
    }


def _remove_s3_kms_unknown(value: object) -> object | None:
    if len(_named_expressions(value, "kms_master_key_id")) != 1:
        return None
    normalized = deepcopy(value)
    rule = _single_nested_block(normalized, "rule")
    defaults = _single_nested_block(rule, "apply_server_side_encryption_by_default")
    if defaults is None or defaults.get("kms_master_key_id") is not True:
        return None
    del defaults["kms_master_key_id"]
    return normalized


def _normalized_unknowns(
    raw: Mapping[str, object],
    item: Mapping[str, object],
    body: Mapping[str, object],
) -> tuple[
    object,
    list[dict[str, object]],
    list[dict[str, object]],
    list[dict[str, object]],
    dict[str, object] | None,
    dict[str, object] | None,
]:
    unknowns = body.get("after_unknown", {})
    bucket_policy_binding = _bucket_policy_binding(raw, item)
    kms_binding = _s3_kms_encryption_binding(raw, item, body)
    normalized = deepcopy(unknowns)
    provider_paths: list[str] = []
    resource_bindings: list[dict[str, object]] = []
    policy_bindings: list[dict[str, object]] = []

    base_address = _instance_base_address(cast(str, item["address"]))

    for field_path in sorted(set(_critical_unknown_paths(unknowns))):
        policy_binding = _policy_document_binding(raw, item, field_path)
        resource_binding = _resource_reference_binding(raw, item, field_path)
        provider_result = _provider_computed_unknown(
            raw,
            item,
            body,
            field_path,
            bucket_policy_binding,
        )
        if field_path == S3_KMS_FIELD_PATH and kms_binding is None:
            resource_binding = None

        accepted_kind: ValueKind | None = None
        if policy_binding is not None:
            policy_bindings.append(policy_binding)
            accepted_kind = ValueKind.REFERENCE
        elif resource_binding is not None:
            resource_bindings.append(resource_binding)
            provider_paths.extend([field_path] if field_path == S3_KMS_FIELD_PATH else [])
            accepted_kind = ValueKind.REFERENCE
        elif field_path == S3_KMS_FIELD_PATH and kms_binding is not None:
            provider_paths.append(field_path)
            accepted_kind = ValueKind.REFERENCE
        elif provider_result is not None:
            provider_record, derived_reference = provider_result
            provider_paths.extend(cast(list[str], provider_record["unknown_paths"]))
            if derived_reference is not None:
                resource_bindings.append(derived_reference)
            accepted_kind = (
                ValueKind.REFERENCE if derived_reference is not None else ValueKind.COMPUTED
            )

        exact_policy_key = (cast(str, item["address"]), field_path)
        base_policy_key = (base_address, field_path)
        configuration = _configuration_resource(
            raw,
            cast(str, item["address"]),
            cast(str, item["type"]),
        )
        configured_policy_sources = (
            _configured_expression_sources(raw, configuration, field_path)
            if configuration is not None
            else None
        )
        if (
            (
                exact_policy_key in PLATFORM_POLICY_DOCUMENT_BINDINGS
                or base_policy_key in PLATFORM_POLICY_DOCUMENT_BINDINGS
            )
            and configured_policy_sources
            and policy_binding is None
        ):
            raise ContractError("Terraform policy-document relationship is malformed")

        if accepted_kind in {ValueKind.REFERENCE, ValueKind.COMPUTED}:
            expected_occurrences = (
                4
                if item["address"] == OPENSEARCH_DOMAIN_ADDRESS
                and field_path == "log_publishing_options[].cloudwatch_log_group_arn"
                else 1
            )
            candidate = _remove_unknown_path(
                normalized,
                field_path,
                expected_occurrences=expected_occurrences,
            )
            if candidate is None:
                return unknowns, [], [], [], bucket_policy_binding, kms_binding
            normalized = candidate

    provider_records: list[dict[str, object]] = []
    if provider_paths:
        provider_records.append(
            {
                "address": item["address"],
                "type": item["type"],
                "unknown_paths": sorted(set(provider_paths)),
            }
        )
    return (
        normalized,
        provider_records,
        resource_bindings,
        policy_bindings,
        bucket_policy_binding,
        kms_binding,
    )


def _contains_sensitive_key(value: object) -> bool:
    if isinstance(value, dict):
        return any(
            str(key).casefold() in SENSITIVE_PLAN_KEYS or _contains_sensitive_key(child)
            for key, child in value.items()
        )
    if isinstance(value, list):
        return any(_contains_sensitive_key(child) for child in value)
    return False


def _contains_non_null_master_password(raw: Mapping[str, object]) -> bool:
    def contains(value: object) -> bool:
        if isinstance(value, dict):
            return any(
                (key == "master_user_password" and child not in (None, "")) or contains(child)
                for key, child in value.items()
            )
        if isinstance(value, list):
            return any(contains(child) for child in value)
        return False

    changes = raw.get("resource_changes")
    if not isinstance(changes, list):
        return False
    return any(
        isinstance(item, dict)
        and isinstance(item.get("change"), dict)
        and (
            contains(cast(dict[str, object], item["change"]).get("before"))
            or contains(cast(dict[str, object], item["change"]).get("after"))
        )
        for item in changes
    )


def _action(actions: Sequence[object]) -> PlanAction:
    normalized = tuple(str(action) for action in actions)
    if normalized == ("create",):
        return PlanAction.CREATE
    if normalized == ("read",):
        return PlanAction.READ
    if normalized == ("no-op",):
        return PlanAction.NO_OP
    if normalized == ("update",):
        return PlanAction.UPDATE
    if normalized in {("delete", "create"), ("create", "delete")}:
        return PlanAction.REPLACE
    if normalized == ("delete",):
        return PlanAction.DELETE
    raise ContractError("Terraform plan contains an unsupported action sequence")


def _provider_computed_unknown_sort_key(
    unknown: dict[str, object],
) -> tuple[str, str, str]:
    return (
        str(unknown["address"]),
        str(unknown["type"]),
        ",".join(cast(list[str], unknown["unknown_paths"])),
    )


def _resource_reference_unknown_sort_key(
    binding: dict[str, object],
) -> tuple[str, str, str, str]:
    return (
        str(binding["address"]),
        str(binding["relationship"]),
        ",".join(cast(list[str], binding["unknown_paths"])),
        ",".join(cast(list[str], binding["source_addresses"])),
    )


def _policy_document_binding_sort_key(
    binding: dict[str, object],
) -> tuple[str, str, str]:
    return (
        str(binding["resource_address"]),
        str(binding["field_path"]),
        str(binding["policy_document_address"]),
    )


def _bucket_policy_binding_sort_key(binding: dict[str, object]) -> tuple[str, str]:
    return str(binding["bucket_address"]), str(binding["policy_address"])


def _kms_encryption_binding_sort_key(
    binding: dict[str, object],
) -> tuple[str, str, str]:
    return (
        str(binding["bucket_address"]),
        str(binding["encryption_address"]),
        str(binding["kms_key_address"]),
    )


def _provider_sensitive_null_sort_key(binding: dict[str, object]) -> tuple[str, str, str, str]:
    return (
        str(binding["address"]),
        str(binding["field_path"]),
        str(binding["relationship"]),
        str(binding["source_address"]),
    )


def normalize_plan(value: object, *, evaluation_time: str) -> dict[str, object]:
    """Produce a minimal policy input and reject sensitive/critical unknown values."""
    parse_utc_timestamp(evaluation_time, "evaluation_time")
    if not isinstance(value, dict):
        raise ContractError("Terraform plan JSON must be an object")
    raw = cast(dict[str, object], value)
    if _contains_sensitive_key(raw):
        raise ContractError("Terraform plan contains prohibited sensitive fields")
    if _contains_non_null_master_password(raw):
        raise ContractError("Terraform plan contains prohibited sensitive fields")
    if raw.get("terraform_version") != "1.16.1":
        raise ContractError("Terraform plan version must be exactly 1.16.1")
    if not isinstance(raw.get("format_version"), str):
        raise ContractError("Terraform plan format_version is missing")
    variables = raw.get("variables")
    changes = raw.get("resource_changes")
    if not isinstance(variables, dict) or not isinstance(changes, list):
        raise ContractError("Terraform plan JSON is missing variables or resource_changes")
    outputs = raw.get("output_changes", {})
    if not isinstance(outputs, dict):
        raise ContractError("OUTPUT_CHANGE_SHAPE_INVALID")
    for output in outputs.values():
        if not isinstance(output, dict):
            raise ContractError("OUTPUT_CHANGE_SHAPE_INVALID")
        for name in ("before_sensitive", "after_sensitive"):
            mask = output.get(name, False)
            kind = classify_plan_value(
                present=name.removesuffix("_sensitive") in output,
                value=output.get(name.removesuffix("_sensitive")),
                unknown=False,
                sensitive=mask,
            )
            if kind is ValueKind.SENSITIVE:
                raise ContractError("OUTPUT_SENSITIVITY_PROHIBITED")
    region = variables.get("aws_region")
    if not isinstance(region, dict):
        raise ContractError("Terraform plan JSON is missing aws_region")

    normalized_changes: list[dict[str, object]] = []
    provider_computed_unknowns: list[dict[str, object]] = []
    resource_reference_unknowns: list[dict[str, object]] = []
    policy_document_bindings: list[dict[str, object]] = []
    bucket_policy_bindings: list[dict[str, object]] = []
    kms_encryption_bindings: list[dict[str, object]] = []
    provider_sensitive_nulls: list[dict[str, object]] = []
    provider_sensitive_before_nulls: list[dict[str, object]] = []
    seen_change_addresses: set[str] = set()
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            raise ContractError("Terraform resource change is malformed")
        body = cast(dict[str, object], item["change"])
        # Resource snapshots are objects. Lists are valid only inside their masks,
        # where Terraform represents repeated blocks or collection attributes.
        for mask_name in ("before_sensitive", "after_sensitive"):
            resource_mask = body.get(mask_name, {})
            if not isinstance(resource_mask, (bool, dict)) or not _valid_sensitivity_shape(
                resource_mask
            ):
                raise ContractError("Terraform sensitivity metadata is malformed")
        before_mask = body.get("before_sensitive", {})
        before_kind = classify_plan_value(
            present="before" in body,
            value=body.get("before"),
            unknown=False,
            sensitive=before_mask,
        )
        normalized_before = deepcopy(body.get("before"))
        if before_kind is ValueKind.SENSITIVE:
            normalized_before, before_mask, record = _normalize_existing_password_metadata(
                raw, item
            )
            provider_sensitive_before_nulls.append(record)
        if before_mask is False:
            before_mask = {}
        if not isinstance(item.get("address"), str) or not isinstance(item.get("type"), str):
            raise ContractError("Terraform resource identity is malformed")
        address = cast(str, item["address"])
        if address in seen_change_addresses:
            raise ContractError("Terraform resource change addresses must be unique")
        seen_change_addresses.add(address)
        normalized_after: object = deepcopy(body.get("after"))
        normalized_sensitive: object = body.get("after_sensitive", {})
        after_kind = classify_plan_value(
            present="after" in body,
            value=body.get("after"),
            unknown=body.get("after_unknown", {}),
            sensitive=normalized_sensitive,
        )
        if normalized_sensitive is False:
            normalized_sensitive = {}
        if after_kind is ValueKind.SENSITIVE:
            sensitive_result = _opensearch_omitted_password_sensitivity(raw, item, body)
            if sensitive_result is None:
                raise ContractError("Terraform plan contains sensitive values")
            normalized_after, normalized_sensitive, sensitive_record = sensitive_result
            provider_sensitive_nulls.append(sensitive_record)
        (
            normalized_unknowns,
            provider_computed_records,
            resource_reference_records,
            policy_document_records,
            bucket_policy_binding,
            kms_encryption_binding,
        ) = (
            ({}, [], [], [], None, None)
            if body.get("actions") == ["delete"]
            and body.get("after") is None
            and body.get("after_unknown", {}) in ({}, False)
            else _normalized_unknowns(raw, item, body)
        )
        if _critical_unknown(normalized_unknowns):
            raise ContractError("Terraform plan contains policy-critical unknown values")
        provider_computed_unknowns.extend(provider_computed_records)
        resource_reference_unknowns.extend(resource_reference_records)
        policy_document_bindings.extend(policy_document_records)
        if bucket_policy_binding is not None:
            bucket_policy_bindings.append(bucket_policy_binding)
        if kms_encryption_binding is not None:
            kms_encryption_bindings.append(kms_encryption_binding)
        normalized_changes.append(
            {
                "address": item.get("address"),
                "type": item.get("type"),
                "change": {
                    "actions": body.get("actions", []),
                    "before": _normalize_known_policy_values(item["type"], normalized_before),
                    "before_sensitive": before_mask,
                    "after": _normalize_known_policy_values(item["type"], normalized_after),
                    "after_unknown": normalized_unknowns,
                    "after_sensitive": normalized_sensitive,
                },
            }
        )
    return {
        "format_version": raw.get("format_version"),
        "terraform_version": raw.get("terraform_version"),
        "variables": {"aws_region": region},
        "evaluation_context": {
            "evaluation_time": evaluation_time,
            "policy_ids": list(POLICY_IDS),
            "provider_computed_unknowns": sorted(
                provider_computed_unknowns,
                key=_provider_computed_unknown_sort_key,
            ),
            "resource_reference_unknowns": sorted(
                resource_reference_unknowns,
                key=_resource_reference_unknown_sort_key,
            ),
            "policy_document_bindings": sorted(
                policy_document_bindings,
                key=_policy_document_binding_sort_key,
            ),
            "s3_bucket_policy_bindings": sorted(
                bucket_policy_bindings,
                key=_bucket_policy_binding_sort_key,
            ),
            "s3_kms_encryption_bindings": sorted(
                kms_encryption_bindings,
                key=_kms_encryption_binding_sort_key,
            ),
            "provider_sensitive_nulls": sorted(
                provider_sensitive_nulls,
                key=_provider_sensitive_null_sort_key,
            ),
            "provider_sensitive_before_nulls": sorted(
                provider_sensitive_before_nulls,
                key=_provider_sensitive_null_sort_key,
            ),
        },
        "resource_changes": normalized_changes,
    }


def _normalize_existing_password_metadata(
    raw: Mapping[str, object],
    item: Mapping[str, object],
) -> tuple[object, object, dict[str, object]]:
    """Use the same narrow proof for existing values without weakening other masks."""
    view = deepcopy(raw)
    changes = view.get("resource_changes")
    if not isinstance(changes, list):
        raise ContractError("BEFORE_SENSITIVITY_PROHIBITED")
    candidate: dict[str, object] | None = None
    for change in changes:
        if not isinstance(change, dict) or not isinstance(change.get("change"), dict):
            raise ContractError("BEFORE_SENSITIVITY_PROHIBITED")
        body = change["change"]
        before = body.get("before")
        if isinstance(before, dict):
            change["change"] = {
                "actions": ["no-op"],
                "before": deepcopy(before),
                "after": deepcopy(before),
                "after_unknown": {},
                "after_sensitive": deepcopy(body.get("before_sensitive", {})),
            }
        if change.get("address") == item.get("address"):
            candidate = change
    if candidate is None:
        raise ContractError("BEFORE_SENSITIVITY_PROHIBITED")
    candidate_body = candidate.get("change")
    if not isinstance(candidate_body, dict):
        raise ContractError("BEFORE_SENSITIVITY_PROHIBITED")
    result = _opensearch_omitted_password_sensitivity(view, candidate, candidate_body)
    if result is None:
        raise ContractError("BEFORE_SENSITIVITY_PROHIBITED")
    return result


def summarize_plan(value: Mapping[str, object]) -> PlanSummary:
    """Return address-sorted normalized plan actions."""
    changes = value.get("resource_changes")
    if not isinstance(changes, list):
        raise ContractError("normalized plan is missing resource_changes")
    records: list[PlanActionRecord] = []
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            raise ContractError("normalized plan change is malformed")
        body = cast(dict[str, object], item["change"])
        actions = body.get("actions")
        if not isinstance(actions, list):
            raise ContractError("normalized plan actions are malformed")
        address = item.get("address")
        resource_type = item.get("type")
        if not isinstance(address, str) or not isinstance(resource_type, str):
            raise ContractError("normalized resource identity is malformed")
        records.append(PlanActionRecord(address, resource_type, _action(actions)))
    return PlanSummary(tuple(sorted(records, key=lambda record: record.address)))


class OpaPolicyRunner:
    """Execute exact OPA eval through an injected argv-only process boundary."""

    def __init__(
        self,
        executable: Path,
        runner: CommandRunner,
        repository_root: Path,
        external_root: Path,
        executable_sha256: str | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> None:
        self._executable = executable
        self._runner = runner
        self._repository_root = repository_root.resolve(strict=True)
        self._external_root = external_root.resolve(strict=False)
        self._executable_sha256 = executable_sha256
        self._environment = {
            key: value
            for key, value in (environment or {}).items()
            if key.upper() in {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
        }

    def verify_version(self) -> None:
        """Require exact OPA 1.20.0 before evaluating a real plan."""
        if (
            self._executable_sha256 is None
            or sha256_file(self._executable) != self._executable_sha256
        ):
            raise ContractError("OPA_EXECUTABLE_IDENTITY_REQUIRED")
        result = self._runner.run(
            (str(self._executable), "version"),
            cwd=self._repository_root,
            environment=self._environment,
            timeout_seconds=60,
        )
        if result.returncode != 0 or result.stdout.splitlines()[:1] != [f"Version: {OPA_VERSION}"]:
            raise ContractError("OPA version must be exactly 1.20.0")

    def evaluate(self, normalized_plan_path: Path) -> ProcessResult:
        """Evaluate real normalized plan JSON without exception or threshold changes."""
        path = ensure_external_path(
            normalized_plan_path, self._external_root, self._repository_root
        )
        self.verify_version()
        load_json_strict(path)
        expected_hash = sha256_file(path)
        policy = self._repository_root / "policies" / "opa" / "terraform_plan.rego"
        exceptions = self._repository_root / "policies" / "opa" / "exceptions.json"
        source_hashes = (sha256_file(policy), sha256_file(exceptions))
        result = self._runner.run(
            (
                str(self._executable),
                "eval",
                "--format=json",
                "--data",
                str(policy),
                "--data",
                str(exceptions),
                "--input",
                str(path),
                "data.enterprise_ai.terraform.plan.decision",
            ),
            cwd=self._repository_root,
            environment=self._environment,
            timeout_seconds=120,
        )
        if result.returncode != 0:
            raise ContractError("OPA real-plan evaluation failed")
        if sha256_file(path) != expected_hash or source_hashes != (
            sha256_file(policy),
            sha256_file(exceptions),
        ):
            raise ContractError("OPA_INPUT_OR_SOURCE_DRIFT")
        parse_production_decision(result.stdout.encode("utf-8"))
        return result

    def evaluate_decision(self, normalized_plan_path: Path) -> dict[str, object]:
        """Return the exact safe decision with independent input/source bindings."""
        result = self.evaluate(normalized_plan_path)
        decision = parse_production_decision(result.stdout.encode("utf-8"))
        return {
            "schema_version": "w5-004.policy-result.v2",
            "allow": decision["allow"],
            "findings": decision["findings"],
            "input_sha256": sha256_file(normalized_plan_path),
            "policy_sha256": sha256_file(
                self._repository_root / "policies/opa/terraform_plan.rego"
            ),
            "exceptions_sha256": sha256_file(
                self._repository_root / "policies/opa/exceptions.json"
            ),
        }


def parse_production_decision(raw: bytes) -> dict[str, object]:
    """Undefined, multiple, malformed or inconsistent OPA decisions fail closed."""
    output = decode_json_strict(raw)
    if not isinstance(output, dict) or set(output) != {"result"}:
        raise ContractError("OPA_RESULT_UNDEFINED_OR_ERROR")
    results = output["result"]
    if not isinstance(results, list) or len(results) != 1 or not isinstance(results[0], dict):
        raise ContractError("OPA_RESULT_CARDINALITY")
    expressions = results[0].get("expressions")
    if (
        not isinstance(expressions, list)
        or len(expressions) != 1
        or not isinstance(expressions[0], dict)
    ):
        raise ContractError("OPA_EXPRESSION_CARDINALITY")
    decision = expressions[0].get("value")
    if not isinstance(decision, dict) or set(decision) != {"schema_version", "allow", "findings"}:
        raise ContractError("OPA_DECISION_FIELDS")
    if (
        decision["schema_version"] != "w5-004.policy-decision.v2"
        or type(decision["allow"]) is not bool
    ):
        raise ContractError("OPA_DECISION_TYPE")
    findings = decision["findings"]
    if not isinstance(findings, list) or decision["allow"] != (len(findings) == 0):
        raise ContractError("OPA_DECISION_INCONSISTENT")
    expected = {
        "schema_version",
        "policy_id",
        "severity",
        "resource_address",
        "category",
        "remediation_code",
        "exception_status",
    }
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != expected
            or any(not isinstance(value, str) for value in finding.values())
            or finding["schema_version"] != "w5-003.policy-finding.v1"
            or finding["policy_id"] not in POLICY_IDS
        ):
            raise ContractError("OPA_FINDING_SCHEMA")
    return cast(dict[str, object], decision)


class ValueKind(StrEnum):
    """Representation categories; no fabricated provider identity is substituted."""

    ABSENT = "ABSENT"
    NULL = "NULL"
    KNOWN = "KNOWN"
    COMPUTED = "COMPUTED"
    SENSITIVE = "SENSITIVE"
    REFERENCE = "REFERENCE"


def _normalize_known_policy_values(resource_type: object, values: object) -> object:
    """Canonicalize only the reviewed IAM grammar fields in the security projection."""
    fields_by_type = {
        "aws_iam_role": ("assume_role_policy",),
        "aws_iam_role_policy": ("policy",),
        "aws_kms_key": ("policy",),
        "aws_s3_bucket_policy": ("policy",),
        "aws_cloudwatch_log_resource_policy": ("policy_document",),
        "aws_opensearch_domain": ("access_policies",),
    }
    if not isinstance(resource_type, str) or not isinstance(values, dict):
        return values
    result = deepcopy(values)
    for field in fields_by_type.get(resource_type, ()):
        value = result.get(field)
        if isinstance(value, str) and value:
            result[field] = canonical_json_bytes(policy_semantic_value(value)).decode("utf-8")
    return result


def classify_plan_value(
    *, present: bool, value: object, unknown: object, sensitive: object
) -> ValueKind:
    """Classify masks before inspecting values; malformed metadata is never false."""
    if not _valid_sensitivity_shape(sensitive) or not _valid_sensitivity_shape(unknown):
        raise ContractError("VALUE_MASK_MALFORMED")
    if _contains_true(sensitive):
        return ValueKind.SENSITIVE
    if _contains_true(unknown):
        return ValueKind.COMPUTED
    if not present:
        return ValueKind.ABSENT
    return ValueKind.NULL if value is None else ValueKind.KNOWN


def policy_semantic_value(raw: str) -> object:
    """Normalize object keys and uniquely SID-keyed statements, not arbitrary arrays."""
    value = decode_json_strict(raw.encode("utf-8"))
    if not isinstance(value, dict):
        raise ContractError("POLICY_DOCUMENT_OBJECT_REQUIRED")
    document = deepcopy(value)
    statements = document.get("Statement")
    if not isinstance(statements, list):
        raise ContractError("POLICY_STATEMENTS_REQUIRED")
    identifiers: set[str] = set()
    all_identified = True
    for statement in statements:
        if not isinstance(statement, dict):
            raise ContractError("POLICY_STATEMENT_ID_REQUIRED")
        identifier = statement.get("Sid")
        if identifier is None:
            all_identified = False
        else:
            if not isinstance(identifier, str) or not identifier or identifier in identifiers:
                raise ContractError("POLICY_STATEMENT_ID_AMBIGUOUS")
            identifiers.add(identifier)
        # Only these IAM grammar fields permit singleton/list equivalence.
        for field in ("Action", "NotAction", "Resource", "NotResource"):
            if isinstance(statement.get(field), str):
                statement[field] = [statement[field]]
    if all_identified:
        document["Statement"] = sorted(statements, key=lambda statement: statement["Sid"])
    return document


W7_001_PROHIBITED_RESOURCE_TYPES = frozenset(
    {
        "aws_cloudwatch_event_rule",
        "aws_cloudwatch_event_target",
        "aws_glue_catalog_database",
        "aws_glue_catalog_table",
        "aws_kms_key",
        "aws_sfn_state_machine",
    }
)


def validate_w7_001_data_foundation_plan(plan: object) -> tuple[str, ...]:
    """Return stable safe codes for the source-only W7-001 plan shape."""

    if not isinstance(plan, dict) or not isinstance(plan.get("resource_changes"), list):
        return ("W7_PLAN_SHAPE_INVALID",)
    findings: set[str] = set()
    bucket_count = 0
    for change in plan["resource_changes"]:
        if not isinstance(change, dict):
            findings.add("W7_PLAN_SHAPE_INVALID")
            continue
        resource_type = change.get("type")
        if resource_type in W7_001_PROHIBITED_RESOURCE_TYPES:
            findings.add("W7_UNAUTHORIZED_RESOURCE")
        if resource_type == "aws_s3_bucket":
            bucket_count += 1
        if resource_type == "aws_s3_bucket_notification":
            change_body = change.get("change")
            if not isinstance(change_body, dict):
                findings.add("W7_PLAN_SHAPE_INVALID")
                continue
            after = change_body.get("after")
            if not isinstance(after, dict) or after.get("eventbridge") is not True:
                findings.add("W7_EVENTBRIDGE_NOTIFICATION_REQUIRED")
    if bucket_count > 1:
        findings.add("W7_MULTIPLE_PLATFORM_BUCKETS")
    return tuple(sorted(findings))
