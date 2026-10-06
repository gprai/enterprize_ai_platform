"""AWS inventory contracts shared by deterministic fakes and the explicit live adapter."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

# W6-004 adds these project-owned live lifecycle surfaces while preserving the
# existing W5 inventory contracts and shared service-linked-role exclusions.
W6_004_NATIVE_SERVICES = (
    "cloudformation",
    "cloudwatch",
    "cost-explorer",
    "dynamodb",
    "ec2",
    "ecr",
    "eks",
    "fis",
    "iam",
    "kms",
    "logs",
    "opensearch",
    "s3",
    "secretsmanager",
    "sns",
    "sts",
    "xray",
)

PUBLIC_CHARGING_PAGES = (
    "https://aws.amazon.com/privatelink/pricing/",
    "https://aws.amazon.com/opensearch-service/pricing/",
    "https://aws.amazon.com/cloudwatch/pricing/",
    "https://aws.amazon.com/s3/pricing/",
    "https://aws.amazon.com/ecr/pricing/",
    "https://aws.amazon.com/kms/pricing/",
    "https://aws.amazon.com/dynamodb/pricing/on-demand/",
    "https://aws.amazon.com/aws-cost-management/aws-cost-explorer/pricing/",
    "https://aws.amazon.com/ec2/pricing/on-demand/",
    "https://aws.amazon.com/inspector/pricing/",
    "https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html",
    "https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-transition-general-considerations.html",
)


class ServiceIdentifier(StrEnum):
    """Complete service-specific cleanup boundary from Source of Truth v1.1."""

    EKS = "EKS"
    ELB = "ELB"
    EBS = "EBS"
    ENI = "ENI"
    EIP = "EIP"
    OPENSEARCH = "OpenSearch"
    S3 = "S3"
    DYNAMODB = "DynamoDB"
    ECR = "ECR"
    CLOUDWATCH_LOGS = "CloudWatch Logs"
    SECRETS_MANAGER = "Secrets Manager"
    KMS = "KMS"
    IAM = "IAM"
    LAMBDA = "Lambda"
    GLUE = "Glue"
    STEP_FUNCTIONS = "Step Functions"
    EVENTBRIDGE = "EventBridge"


class ResourceState(StrEnum):
    """States needed by the offline cleanup classifier."""

    ACTIVE = "ACTIVE"
    PENDING_DELETION = "PENDING_DELETION"
    UNKNOWN = "UNKNOWN"
    ABSENT = "ABSENT"


@dataclass(frozen=True)
class InventoryResource:
    """Sanitized resource metadata returned by an approved inventory provider."""

    service: ServiceIdentifier
    resource_id: str
    tags: Mapping[str, str]
    state: ResourceState
    scheduled_deletion_at: str | None = None
    account_id: str = "526338061652"
    region: str = "ap-southeast-1"
    cost_bearing: bool = True
    owner_classification: str = "PROJECT_MANAGED"


@dataclass(frozen=True)
class KmsSchedulingEvidence:
    """Owner-approved original scheduling fact, not a moving verification deadline."""

    key_identity: str
    account_id: str
    region: str
    scheduled_at: str
    deletion_at: str
    window_days: int
    approval_id: str
    evidence_sha256: str


@dataclass(frozen=True)
class NativeReadSpec:
    """One bounded, owner-reviewed service read and its exact result projection."""

    address: str
    resource_type: str
    service: str
    method: str
    arguments_json: str
    result_key: str
    request_token: str | None
    response_token: str | None
    maximum_pages: int
    maximum_items: int
    expected_native_identity: str
    identity_key: str


@dataclass(frozen=True)
class NativeAssertion:
    """An exact owner-reviewed native projection; values stay in private memory."""

    category: str
    probe: NativeReadSpec
    expected_fields_json: str


@dataclass(frozen=True)
class NativeOwnershipBinding:
    """Native consumer-to-parent field, not a name-based ownership assumption."""

    consumer_field: str
    parent_identity: str


@dataclass(frozen=True)
class NativeTarget:
    """One resource's independent identity, ownership and configuration checks."""

    address: str
    resource_type: str
    presence: NativeReadSpec
    assertions: tuple[NativeAssertion, ...]
    cost_bearing: bool
    ownership_binding: NativeOwnershipBinding | None = None


@dataclass(frozen=True)
class NativeTargetBundle:
    """Versioned input for exact native reads, not an asserted successful inventory."""

    schema_version: str
    targets: tuple[NativeTarget, ...]


@dataclass(frozen=True)
class NativeScanSpec:
    """Complete service enumeration with tag reads where listing omits tags."""

    coverage: str
    service: str
    method: str
    arguments_json: str
    result_key: str
    identity_key: str
    tags_key: str
    tag_method: str | None
    tag_argument: str | None
    tag_result_key: str | None
    request_token: str | None
    response_token: str | None
    maximum_pages: int
    maximum_items: int
    detail_method: str | None
    detail_argument: str | None
    detail_identity_key: str | None
    tag_identity_key: str | None


@dataclass(frozen=True)
class NativeScanBundle:
    schema_version: str
    scans: tuple[NativeScanSpec, ...]
    retained_identities: tuple[tuple[str, str], ...]
    excluded_identities: tuple[tuple[str, str, str], ...]


class InventoryUnavailable(RuntimeError):
    """Raised when required inventory cannot be proven."""


@dataclass(frozen=True)
class DiagnosticCollectionLimits:
    """The exact owner-approved caps; runtime JSON cannot increase them."""

    requests: int = 600
    elapsed_seconds: int = 900
    pages: int = 10
    items_per_query: int = 5000
    discovery_items: int = 20000
    caller_groups: int = 20
    simulation_requests: int = 24
    billing_requests: int = 6
    response_bytes: int = 16 * 1024 * 1024
    state_bytes: int = 64 * 1024 * 1024


DIAGNOSTIC_LIMITS = DiagnosticCollectionLimits()
RESOLUTION_LIMITS = DiagnosticCollectionLimits(requests=200, pages=3, billing_requests=3)
PREREQUISITE_LIMITS = DiagnosticCollectionLimits(
    requests=80, elapsed_seconds=600, pages=3, billing_requests=3, simulation_requests=15
)
PREREQUISITE_OPERATION_ID = "w5-004-prerequisite-evidence-001"
PREREQUISITE_DIRECTORY = "prerequisite-evidence-001"
PREREQUISITE_CORRECTION_OPERATION = "w5-004-prerequisite-evidence-002"
PREREQUISITE_CORRECTION_DIRECTORY = "prerequisite-evidence-002"
PREREQUISITE_CORRECTION_LIMITS = DiagnosticCollectionLimits(
    requests=40, elapsed_seconds=600, pages=3, billing_requests=0, simulation_requests=15
)
PREREQUISITE_ROUTES = ("rtb-0a1a1df9664db7a43", "rtb-0b3d3245554c47fa2")
PREREQUISITE_ROLES = (
    "AWSControlTowerAdmin",
    "AWSControlTowerCloudTrailRole",
    "AWSControlTowerConfigAggregatorRoleForOrganizations",
    "AWSControlTowerStackSetRole",
    "AWSReservedSSO_AWSAdministratorAccess_e11a316dc857def9",
    "AWSReservedSSO_AWSPowerUserAccess_1ec693b2375644a4",
    "AWSReservedSSO_AWSReadOnlyAccess_72b03c6b0781ff74",
    "AWSReservedSSO_AWSServiceCatalogAdminFullAccess_f72cea9c94b68841",  # pragma: allowlist secret
    "AWSReservedSSO_AWSServiceCatalogEndUserAccess_876d9315c50c4784",  # pragma: allowlist secret
    "github-actions-oidc-role-ui2",
    "github-actions-terraform-platform-role",
    "Helloworlddemo-role-rw52sxer",
)
PREREQUISITE_POLICY = (
    "arn:aws:iam::526338061652:policy/service-role/"
    "AWSLambdaBasicExecutionRole-b48d6859-d98d-40eb-b786-c933f136e828"
)
PREREQUISITE_LOG_NAMES = tuple(
    "/aws/OpenSearchService/domains/enterprise-ai-sandbox/" + suffix
    for suffix in ("application-logs", "audit-logs", "index-slow-logs", "search-slow-logs")
)
PREREQUISITE_LOG_ACTIONS = (
    "logs:CreateLogGroup",
    "logs:TagResource",
    "logs:TagLogGroup",
    "logs:AssociateKmsKey",
    "logs:PutRetentionPolicy",
)
PREREQUISITE_CHECK_IDS = (
    "aws_identity",
    "bootstrap_state",
    "platform_state",
    "state_selectors",
    "bootstrap_retention",
    "operating_envelope",
    "relationship/route",
    *("relationship/role/" + name for name in PREREQUISITE_ROLES),
    "relationship/policy/PermissionsPolicy",
    "relationship/policy/PermissionsBoundary",
    "authorization/caller",
    "authorization/context",
    *("authorization/" + action for action in PREREQUISITE_LOG_ACTIONS),
    "authorization/summary",
    "authorization/kms",
    "storage/bootstrap/versions",
    "storage/bootstrap/uploads",
    "storage/platform/versions",
    "storage/platform/uploads",
    "storage/ecr",
    "storage/lock_table",
    "billing/gross_and_offsets",
    "lifecycle_bound",
    "bootstrap_state_preserved",
    "platform_state_preserved",
    "final_caller",
    "final_preservation",
)
PREREQUISITE_CORRECTION_CHECK_IDS = tuple(
    name
    for name in PREREQUISITE_CHECK_IDS
    if name != "relationship/route" and not name.startswith(("storage/", "billing/"))
)
RESOLUTION_OPERATION_ID = "w5-004-resolution-evidence-001"
RESOLUTION_DIRECTORY = "resolution-evidence-001"
RESOLUTION_FOLLOWUP_DIRECTORY = "resolution-evidence-002"
RESOLUTION_FOLLOWUP_OPERATION_ID = "w5-004-resolution-evidence-002"
RESOLUTION_FOLLOWUP_EVIDENCE_SHA256 = (
    "c61481eb73cc5c3b7546527db357b460d7f59d8f3d4cb963bd16221f64c4c0c7"  # pragma: allowlist secret
)
RESOLUTION_FOLLOWUP_IDENTITY_SHA256 = (
    "47c9889dd6062f4ccc5a993ad4998449600b7e46a201f165d8020c42ab134b74"  # pragma: allowlist secret
)
RESOLUTION_BILLING_START = "2026-09-08"
RESOLUTION_BILLING_END = "2026-09-13"
RESOLUTION_EVENTS_START = "2026-09-10T07:42:00Z"
RESOLUTION_EVENTS_END = "2026-09-10T07:43:00Z"
# Public integrity digest of the completed, immutable diagnostic.
RESOLUTION_EVIDENCE_SHA256 = (
    "2d28abad244d6802667e56294b9cde5beb0896848df56a067a47ad43872c3789"  # pragma: allowlist secret
)


class AwsInventoryProvider(Protocol):
    """Dependency-injected boundary for tag and native service discovery."""

    def list_tagged_resources(
        self, required_tags: Mapping[str, str]
    ) -> Sequence[InventoryResource]:
        """Return Resource Groups Tagging API-equivalent results."""
        ...

    def list_service_resources(self, service: ServiceIdentifier) -> Sequence[InventoryResource]:
        """Return native service-equivalent results for one service."""
        ...


class UnavailableAwsInventoryProvider:
    """Default runtime boundary that refuses to claim live cleanliness."""

    def list_tagged_resources(
        self, required_tags: Mapping[str, str]
    ) -> Sequence[InventoryResource]:
        """Fail because W1-004 has no approved live adapter."""
        del required_tags
        raise InventoryUnavailable("AWS inventory provider is unavailable")

    def list_service_resources(self, service: ServiceIdentifier) -> Sequence[InventoryResource]:
        """Fail because W1-004 has no approved native service adapter."""
        del service
        raise InventoryUnavailable("AWS inventory provider is unavailable")


def diagnostic_discovery_profile() -> NativeScanBundle:
    """Fixed, unfiltered read catalog for the approved diagnostic, never a purge profile."""
    from .lifecycle_io import canonical_json_bytes
    from .lifecycle_models import OPERATIONAL_SCHEMA_VERSION

    # coverage, service, enumeration, result, identity, tags, request/response tokens,
    # optional detail method/argument/identity, optional tag method/argument/result.
    rows: tuple[
        tuple[
            str,
            str,
            str,
            str,
            str,
            str,
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
        ],
        ...,
    ] = (
        (
            "EC2_NETWORK",
            "ec2",
            "describe_vpcs",
            "Vpcs",
            "VpcId",
            "Tags",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "EC2_SUBNETS",
            "ec2",
            "describe_subnets",
            "Subnets",
            "SubnetId",
            "Tags",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "EC2_ROUTES",
            "ec2",
            "describe_route_tables",
            "RouteTables",
            "RouteTableId",
            "Tags",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "EC2_SECURITY_GROUPS",
            "ec2",
            "describe_security_groups",
            "SecurityGroups",
            "GroupId",
            "Tags",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "EC2_ENDPOINTS",
            "ec2",
            "describe_vpc_endpoints",
            "VpcEndpoints",
            "VpcEndpointId",
            "Tags",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "EBS",
            "ec2",
            "describe_volumes",
            "Volumes",
            "VolumeId",
            "Tags",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "ENI",
            "ec2",
            "describe_network_interfaces",
            "NetworkInterfaces",
            "NetworkInterfaceId",
            "TagSet",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "EIP",
            "ec2",
            "describe_addresses",
            "Addresses",
            "AllocationId",
            "Tags",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "EKS",
            "eks",
            "list_clusters",
            "clusters",
            "",
            "cluster.tags",
            "nextToken",
            "nextToken",
            "describe_cluster",
            "name",
            "cluster.arn",
            None,
            None,
            None,
        ),
        (
            "ELB",
            "elbv2",
            "describe_load_balancers",
            "LoadBalancers",
            "LoadBalancerArn",
            "",
            "Marker",
            "NextMarker",
            None,
            None,
            None,
            "describe_tags",
            "ResourceArns",
            "TagDescriptions.0.Tags",
        ),
        (
            "TARGET_GROUPS",
            "elbv2",
            "describe_target_groups",
            "TargetGroups",
            "TargetGroupArn",
            "",
            "Marker",
            "NextMarker",
            None,
            None,
            None,
            "describe_tags",
            "ResourceArns",
            "TagDescriptions.0.Tags",
        ),
        (
            "OPENSEARCH",
            "opensearch",
            "list_domain_names",
            "DomainNames",
            "DomainName",
            "",
            None,
            None,
            "describe_domain",
            "DomainName",
            "DomainStatus.ARN",
            "list_tags",
            "ARN",
            "TagList",
        ),
        (
            "S3",
            "s3",
            "list_buckets",
            "Buckets",
            "Name",
            "",
            "ContinuationToken",
            "ContinuationToken",
            None,
            None,
            None,
            "get_bucket_tagging",
            "Bucket",
            "TagSet",
        ),
        (
            "DYNAMODB",
            "dynamodb",
            "list_tables",
            "TableNames",
            "",
            "",
            "ExclusiveStartTableName",
            "LastEvaluatedTableName",
            "describe_table",
            "TableName",
            "Table.TableArn",
            "list_tags_of_resource",
            "ResourceArn",
            "Tags",
        ),
        (
            "ECR",
            "ecr",
            "describe_repositories",
            "repositories",
            "repositoryArn",
            "",
            "nextToken",
            "nextToken",
            None,
            None,
            None,
            "list_tags_for_resource",
            "resourceArn",
            "tags",
        ),
        (
            "CLOUDWATCH_LOGS",
            "logs",
            "describe_log_groups",
            "logGroups",
            "logGroupArn",
            "",
            "nextToken",
            "nextToken",
            None,
            None,
            None,
            "list_tags_for_resource",
            "resourceArn",
            "tags",
        ),
        (
            "CLOUDWATCH_ALARMS",
            "cloudwatch",
            "describe_alarms",
            "MetricAlarms",
            "AlarmArn",
            "",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            "list_tags_for_resource",
            "ResourceARN",
            "Tags",
        ),
        (
            "SECRETS_MANAGER",
            "secretsmanager",
            "list_secrets",
            "SecretList",
            "ARN",
            "Tags",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
        (
            "KMS",
            "kms",
            "list_keys",
            "Keys",
            "KeyArn",
            "",
            "Marker",
            "NextMarker",
            None,
            None,
            None,
            "list_resource_tags",
            "KeyId",
            "Tags",
        ),
        (
            "IAM_ROLES",
            "iam",
            "list_roles",
            "Roles",
            "RoleName",
            "Role.Tags",
            "Marker",
            "Marker",
            "get_role",
            "RoleName",
            "Role.Arn",
            None,
            None,
            None,
        ),
        (
            "IAM_POLICIES",
            "iam",
            "list_policies",
            "Policies",
            "Arn",
            "",
            "Marker",
            "Marker",
            None,
            None,
            None,
            "list_policy_tags",
            "PolicyArn",
            "Tags",
        ),
        (
            "LAMBDA",
            "lambda",
            "list_functions",
            "Functions",
            "FunctionArn",
            "",
            "Marker",
            "NextMarker",
            None,
            None,
            None,
            "list_tags",
            "Resource",
            "Tags",
        ),
        (
            "GLUE",
            "glue",
            "get_jobs",
            "Jobs",
            "Name",
            "",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            "get_tags",
            "ResourceArn",
            "Tags",
        ),
        (
            "STEP_FUNCTIONS",
            "stepfunctions",
            "list_state_machines",
            "stateMachines",
            "stateMachineArn",
            "",
            "nextToken",
            "nextToken",
            None,
            None,
            None,
            "list_tags_for_resource",
            "resourceArn",
            "tags",
        ),
        (
            "EVENTBRIDGE",
            "events",
            "list_rules",
            "Rules",
            "Arn",
            "",
            "NextToken",
            "NextToken",
            None,
            None,
            None,
            "list_tags_for_resource",
            "ResourceARN",
            "Tags",
        ),
        (
            "TAG_API",
            "resourcegroupstaggingapi",
            "get_resources",
            "ResourceTagMappingList",
            "ResourceARN",
            "Tags",
            "PaginationToken",
            "PaginationToken",
            None,
            None,
            None,
            None,
            None,
            None,
        ),
    )
    scans: list[NativeScanSpec] = []
    for (
        coverage,
        service,
        method,
        result,
        identity,
        tags,
        request,
        response,
        detail,
        argument,
        detail_id,
        tag_method,
        tag_argument,
        tag_result,
    ) in rows:
        arguments: dict[str, object] = {"Scope": "Local"} if coverage == "IAM_POLICIES" else {}
        if coverage == "SECRETS_MANAGER":
            arguments = {"IncludePlannedDeletion": True}
        if coverage == "CLOUDWATCH_ALARMS":
            arguments = {"AlarmTypes": ["MetricAlarm", "CompositeAlarm"]}
        scans.append(
            NativeScanSpec(
                coverage,
                service,
                method,
                canonical_json_bytes(arguments).decode(),
                result,
                identity,
                tags,
                tag_method,
                tag_argument,
                tag_result,
                request,
                response,
                DIAGNOSTIC_LIMITS.pages,
                DIAGNOSTIC_LIMITS.items_per_query,
                detail,
                argument,
                detail_id,
                None,
            )
        )
    return NativeScanBundle(OPERATIONAL_SCHEMA_VERSION, tuple(scans), (), ())


def diagnostic_policy_templates(scope: str) -> dict[str, object]:
    """Reviewed source semantics, not policies copied from a live observation.

    Sources: infra/bootstrap/main.tf and infra/modules/{kms,iam,storage,opensearch}.
    Whole-token state references are resolved privately only after state hash verification.
    """
    from .contracts import ContractError

    if scope not in {"bootstrap", "platform"}:
        raise ContractError("DIAGNOSTIC_PROFILE_SCOPE")
    account = "526338061652"
    region = "ap-southeast-1"
    role_prefix = f"arn:aws:iam::{account}:role/"
    root = f"arn:aws:iam::{account}:root"
    domain = f"arn:aws:es:{region}:{account}:domain/enterprise-ai-sandbox"
    bucket = (
        "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"
        if scope == "bootstrap"
        else "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"
    )
    bucket_arn = "arn:aws:s3:::" + bucket
    key = "state://module.kms.aws_kms_key.this#arn"

    def one(values: list[str]) -> object:
        return values[0] if len(values) == 1 else values

    def statement(
        sid: str,
        actions: str,
        resources: list[str],
        principal: object = None,
        conditions: dict[str, object] | None = None,
        effect: str = "Allow",
    ) -> dict[str, object]:
        result: dict[str, object] = {
            "Sid": sid,
            "Effect": effect,
            "Action": one(actions.split()),
            "Resource": one(resources),
        }
        if principal is not None:
            result["Principal"] = principal
        if conditions:
            result["Condition"] = conditions
        return result

    def document(*statements: dict[str, object]) -> dict[str, object]:
        return {"Version": "2012-10-17", "Statement": list(statements)}

    crypto = (
        "kms:Decrypt kms:DescribeKey kms:Encrypt kms:GenerateDataKey "
        "kms:GenerateDataKeyWithoutPlaintext kms:ReEncryptFrom kms:ReEncryptTo"
    )
    administration = (
        "kms:CancelKeyDeletion kms:CreateAlias kms:DeleteAlias kms:DescribeKey "
        "kms:DisableKey kms:EnableKey kms:EnableKeyRotation kms:GetKeyPolicy "
        "kms:GetKeyRotationStatus kms:ListResourceTags kms:PutKeyPolicy "
        "kms:ScheduleKeyDeletion kms:TagResource kms:UntagResource kms:UpdateAlias "
        "kms:UpdateKeyDescription"
    )
    tls_actions = (
        "s3:GetObject s3:PutObject s3:DeleteObject s3:ListBucket"
        if scope == "bootstrap"
        else (
            "s3:AbortMultipartUpload s3:DeleteObject s3:GetBucketLocation s3:GetObject "
            "s3:ListBucket s3:ListBucketMultipartUploads s3:ListMultipartUploadParts s3:PutObject"
        )
    )
    result: dict[str, object] = {
        "tls": document(
            statement(
                "DenyNonTLSStateAccess" if scope == "bootstrap" else "DenyNonTLSPlatformAccess",
                tls_actions,
                [bucket_arn, bucket_arn + "/*"],
                "*",
                {"Bool": {"aws:SecureTransport": "false"}},
                "Deny",
            )
        )
    }
    if scope == "bootstrap":
        result["kms"] = document(
            statement("EnableExactAccountAdministration", administration, ["*"], {"AWS": root}),
            statement("AllowExactAccountStateCryptography", crypto, ["*"], {"AWS": root}),
            statement(
                "AllowExactAccountDynamoDBStateGrant",
                "kms:CreateGrant",
                ["*"],
                {"AWS": root},
                {
                    "StringEquals": {"kms:CallerAccount": account},
                    "StringLike": {"kms:ViaService": "dynamodb.*.amazonaws.com"},
                },
            ),
        )
        return result
    log_arns = [
        f"arn:aws:logs:{region}:{account}:log-group:/aws/OpenSearchService/domains/"
        "enterprise-ai-sandbox/" + suffix
        for suffix in ("application-logs", "audit-logs", "index-slow-logs", "search-slow-logs")
    ]
    runtime = role_prefix + "enterprise-ai-sandbox-runtime"
    ingestion = role_prefix + "enterprise-ai-sandbox-ingestion"
    administrator = role_prefix + "enterprise-ai-sandbox-opensearch-admin"
    result["kms"] = document(
        statement(
            "EnableExactAccountKeyAdministration",
            administration + " kms:CreateGrant kms:ListGrants kms:RevokeGrant",
            ["*"],
            {"AWS": root},
        ),
        statement(
            "AllowExactWorkloadCryptography",
            crypto,
            ["*"],
            {"AWS": root},
            {"StringEquals": {"aws:PrincipalArn": [runtime, ingestion]}},
        ),
        statement(
            "AllowExactOpenSearchLogEncryption",
            crypto,
            ["*"],
            {"Service": "logs.ap-southeast-1.amazonaws.com"},
            {"ArnEquals": {"kms:EncryptionContext:aws:logs:arn": log_arns}},
        ),
    )
    # Trust policies do not contain Resource, unlike permission policies.
    for name in ("runtime", "ingestion", "opensearch_administrator", "github_oidc"):
        if name in {"runtime", "ingestion"}:
            trust: dict[str, object] = {
                "Sid": "ExactPodIdentity" + name.title() + "Trust",
                "Effect": "Allow",
                "Action": ["sts:AssumeRole", "sts:TagSession"],
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Condition": {
                    "StringEquals": {
                        "aws:RequestTag/kubernetes-namespace": "enterprise-ai-sandbox",
                        "aws:RequestTag/kubernetes-service-account": "enterprise-ai-" + name,
                    }
                },
            }
        elif name == "opensearch_administrator":
            trust = {
                "Sid": "TimeBoundExactSandboxAdministrator",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": f"arn:aws:iam::{account}:user/finopsinfra"},
                "Condition": {"DateLessThan": {"aws:CurrentTime": "2026-09-30T15:59:59Z"}},
            }
        else:
            trust = {
                "Sid": "ExactGitHubEnvironmentTrust",
                "Effect": "Allow",
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Principal": {
                    "Federated": (
                        f"arn:aws:iam::{account}:oidc-provider/token.actions.githubusercontent.com"
                    )
                },
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:sub": (
                            "repo:gprai/enterprize_ai_platform:environment:sandbox"
                        ),
                    }
                },
            }
        result[name + "_trust"] = document(trust)
    result["runtime"] = document(
        statement(
            "InvokeExactApprovedInferenceProfile",
            "bedrock:InvokeModel",
            ["*"],
            conditions={
                "StringEquals": {
                    "bedrock:InferenceProfileArn": f"arn:aws:bedrock:{region}:{account}:"
                    "inference-profile/global.amazon.nova-2-lite-v1:0",
                    "aws:RequestedRegion": region,
                    "aws:PrincipalAccount": account,
                },
                "ArnEquals": {"aws:PrincipalArn": runtime},
                "DateLessThan": {"aws:CurrentTime": "expiry://resource"},
            },
        ),
        statement("RuntimeReadPlatformObjects", "s3:GetObject", [bucket_arn + "/*"]),
        statement("RuntimeListPlatformBucket", "s3:ListBucket", [bucket_arn]),
        statement("RuntimeUsePlatformKey", "kms:Decrypt kms:DescribeKey", [key]),
        statement(
            "RuntimeOpenSearchDataPlane",
            "es:ESHttpGet es:ESHttpHead es:ESHttpPost",
            [domain + "/*"],
        ),
    )
    http = "es:ESHttpDelete es:ESHttpGet es:ESHttpHead es:ESHttpPatch es:ESHttpPost es:ESHttpPut"
    result["ingestion"] = document(
        statement(
            "IngestionPlatformObjects",
            "s3:AbortMultipartUpload s3:DeleteObject s3:GetObject "
            "s3:ListMultipartUploadParts s3:PutObject",
            [bucket_arn + "/*"],
        ),
        statement(
            "IngestionListPlatformBucket",
            "s3:ListBucket s3:ListBucketMultipartUploads",
            [bucket_arn],
        ),
        statement("IngestionUsePlatformKey", crypto, [key]),
        statement("IngestionOpenSearchDataPlane", http, [domain + "/*"]),
    )
    result["log_delivery"] = document(
        statement(
            "ExactOpenSearchLogDelivery",
            "logs:CreateLogStream logs:PutLogEvents",
            [arn + ":*" for arn in log_arns],
            {"Service": "es.amazonaws.com"},
            {"StringEquals": {"aws:SourceAccount": account}, "ArnLike": {"aws:SourceArn": domain}},
        )
    )
    result["domain_access"] = document(
        statement(
            "ExactSandboxRoleDataPlaneAccess",
            http,
            [domain + "/*"],
            {"AWS": [ingestion, administrator]},
        )
    )
    return result


def diagnostic_resource_profile(scope: str) -> NativeTargetBundle:
    """Build all native probes from fixed reviewed topology, including absent resources.

    Known names come from the approved HCL. Provider IDs are whole-token state references;
    no absent resource requires an invented provider ID. This is diagnostic data only.
    """
    from .contracts import ContractError, stable_cleanup_tags
    from .lifecycle_io import canonical_json_bytes
    from .lifecycle_models import OPERATIONAL_SCHEMA_VERSION

    if scope not in {"bootstrap", "platform"}:
        raise ContractError("DIAGNOSTIC_PROFILE_SCOPE")
    policies = diagnostic_policy_templates(scope)
    targets: list[NativeTarget] = []
    tags: dict[str, object] = {**stable_cleanup_tags("sandbox"), "ExpiresAt": "expiry://resource"}
    account = "526338061652"
    region = "ap-southeast-1"

    def reference(address: str, field: str = "id") -> str:
        return "state://" + address + "#" + field

    def probe(
        address: str,
        kind: str,
        service: str,
        method: str,
        arguments: dict[str, object],
        result: str,
        identity_key: str,
        identity: str,
        tokens: tuple[str, str] | None = None,
    ) -> NativeReadSpec:
        return NativeReadSpec(
            address,
            kind,
            service,
            method,
            canonical_json_bytes(arguments).decode(),
            result,
            None if tokens is None else tokens[0],
            None if tokens is None else tokens[1],
            10 if tokens else 1,
            5000,
            identity,
            identity_key,
        )

    def assertion(
        category: str, read: NativeReadSpec, fields: dict[str, object]
    ) -> NativeAssertion:
        return NativeAssertion(category, read, canonical_json_bytes(fields).decode())

    def target(
        presence: NativeReadSpec,
        ownership: NativeAssertion,
        configuration: tuple[NativeAssertion, ...],
        *,
        cost: bool = False,
        binding: NativeOwnershipBinding | None = None,
    ) -> None:
        targets.append(
            NativeTarget(
                presence.address,
                presence.resource_type,
                presence,
                (ownership, *configuration),
                cost,
                binding,
            )
        )

    key_address = (
        "aws_kms_key.terraform_state" if scope == "bootstrap" else "module.kms.aws_kms_key.this"
    )
    key_id = reference(key_address)
    key_arn = reference(key_address, "arn")
    read = probe(
        key_address,
        "aws_kms_key",
        "kms",
        "describe_key",
        {"KeyId": key_id},
        "KeyMetadata",
        "KeyId",
        key_id,
    )
    key_tags = probe(
        key_address,
        "aws_kms_key",
        "kms",
        "list_resource_tags",
        {"KeyId": key_id},
        "",
        "",
        key_id,
        ("Marker", "NextMarker"),
    )
    rotation = probe(
        key_address,
        "aws_kms_key",
        "kms",
        "get_key_rotation_status",
        {"KeyId": key_id},
        "",
        "",
        key_id,
    )
    key_policy = probe(
        key_address,
        "aws_kms_key",
        "kms",
        "get_key_policy",
        {"KeyId": key_id, "PolicyName": "default"},
        "",
        "",
        key_id,
    )
    target(
        read,
        assertion("OWNERSHIP", key_tags, {"Tags": tags}),
        (
            assertion("CONFIGURATION", read, {"KeyState": "Enabled", "KeyManager": "CUSTOMER"}),
            assertion("CONFIGURATION", rotation, {"KeyRotationEnabled": True}),
            assertion(
                "CONFIGURATION", key_policy, {"Policy.@diagnostic_policy_sha256": policies["kms"]}
            ),
        ),
        cost=True,
    )
    alias_address = (
        "aws_kms_alias.terraform_state" if scope == "bootstrap" else "module.kms.aws_kms_alias.this"
    )
    alias_name = "alias/enterprise-ai-platform-sandbox" + (
        "-terraform-state" if scope == "bootstrap" else ""
    )
    read = probe(
        alias_address,
        "aws_kms_alias",
        "kms",
        "list_aliases",
        {"KeyId": key_id},
        "Aliases",
        "AliasName",
        alias_name,
        ("Marker", "NextMarker"),
    )
    parent = probe(
        alias_address,
        "aws_kms_alias",
        "kms",
        "list_resource_tags",
        {"KeyId": key_id},
        "",
        "",
        key_id,
        ("Marker", "NextMarker"),
    )
    target(
        read,
        assertion("OWNERSHIP", parent, {"Tags": tags}),
        (assertion("CONFIGURATION", read, {"AliasName": alias_name, "TargetKeyId": key_id}),),
        binding=NativeOwnershipBinding("TargetKeyId", key_id),
    )

    bucket = (
        "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"
        if scope == "bootstrap"
        else "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"
    )
    prefix = "" if scope == "bootstrap" else "module.storage."
    suffix = "terraform_state" if scope == "bootstrap" else "this"
    lifecycle_rules: list[dict[str, object]] = [
        {
            "ID": "abort-incomplete-multipart-uploads"
            if scope == "bootstrap"
            else "abort-incomplete-and-expire-noncurrent",
            "Status": "Enabled",
            "Filter": {},
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 7},
        }
    ]
    if scope == "platform":
        lifecycle_rules[0]["NoncurrentVersionExpiration"] = {"NoncurrentDays": 30}
        lifecycle_rules.extend(
            {
                "ID": "expire-" + name,
                "Status": "Enabled",
                "Filter": {"Prefix": name + "/"},
                "Expiration": {"Days": 30},
            }
            for name in ("tmp", "test")
        )
    bucket_checks: tuple[tuple[str, str, dict[str, object]], ...] = (
        ("aws_s3_bucket", "get_bucket_location", {"LocationConstraint": region}),
        (
            "aws_s3_bucket_ownership_controls",
            "get_bucket_ownership_controls",
            {"OwnershipControls.Rules.0.ObjectOwnership": "BucketOwnerEnforced"},
        ),
        (
            "aws_s3_bucket_public_access_block",
            "get_public_access_block",
            {
                "PublicAccessBlockConfiguration." + name: True
                for name in (
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                )
            },
        ),
        ("aws_s3_bucket_versioning", "get_bucket_versioning", {"Status": "Enabled"}),
        (
            "aws_s3_bucket_server_side_encryption_configuration",
            "get_bucket_encryption",
            {
                "ServerSideEncryptionConfiguration.Rules.0.ApplyServerSideEncryptionByDefault."
                "SSEAlgorithm": "aws:kms",
                "ServerSideEncryptionConfiguration.Rules.0.ApplyServerSideEncryptionByDefault."
                "KMSMasterKeyID": key_arn,
                "ServerSideEncryptionConfiguration.Rules.0.BucketKeyEnabled": True,
            },
        ),
        (
            "aws_s3_bucket_lifecycle_configuration",
            "get_bucket_lifecycle_configuration",
            {"Rules.@unordered": lifecycle_rules},
        ),
        (
            "aws_s3_bucket_policy",
            "get_bucket_policy",
            {"Policy.@diagnostic_policy_sha256": policies["tls"]},
        ),
    )
    for kind, method, expectations in bucket_checks:
        name = suffix
        if kind == "aws_s3_bucket_policy":
            name = "terraform_state_tls" if scope == "bootstrap" else "tls_only"
        address = prefix + kind + "." + name
        arguments: dict[str, object] = {"Bucket": bucket, "ExpectedBucketOwner": account}
        read = probe(address, kind, "s3", method, arguments, "", "", bucket)
        owner = probe(address, kind, "s3", "get_bucket_tagging", arguments, "", "", bucket)
        target(
            read,
            assertion("OWNERSHIP", owner, {"TagSet": tags}),
            (assertion("CONFIGURATION", read, expectations),),
            cost=kind == "aws_s3_bucket",
        )
    if scope == "bootstrap":
        address = "aws_dynamodb_table.terraform_lock"
        name = "enterprise-ai-platform-sandbox-tflock"
        arn = f"arn:aws:dynamodb:{region}:{account}:table/{name}"
        read = probe(
            address,
            "aws_dynamodb_table",
            "dynamodb",
            "describe_table",
            {"TableName": name},
            "Table",
            "TableName",
            name,
        )
        owner = probe(
            address,
            "aws_dynamodb_table",
            "dynamodb",
            "list_tags_of_resource",
            {"ResourceArn": arn},
            "",
            "",
            arn,
            ("NextToken", "NextToken"),
        )
        backup = probe(
            address,
            "aws_dynamodb_table",
            "dynamodb",
            "describe_continuous_backups",
            {"TableName": name},
            "",
            "",
            name,
        )
        target(
            read,
            assertion("OWNERSHIP", owner, {"Tags": tags}),
            (
                assertion(
                    "CONFIGURATION",
                    read,
                    {
                        "TableStatus": "ACTIVE",
                        "BillingModeSummary.BillingMode": "PAY_PER_REQUEST",
                        "SSEDescription.SSEType": "KMS",
                        "SSEDescription.KMSMasterKeyArn": key_arn,
                        "KeySchema": [{"AttributeName": "LockID", "KeyType": "HASH"}],
                        "AttributeDefinitions": [{"AttributeName": "LockID", "AttributeType": "S"}],
                    },
                ),
                assertion(
                    "CONFIGURATION",
                    backup,
                    {
                        "ContinuousBackupsDescription.PointInTimeRecoveryDescription."
                        "PointInTimeRecoveryStatus": "ENABLED",
                    },
                ),
            ),
            cost=True,
            binding=NativeOwnershipBinding("TableArn", arn),
        )
        return NativeTargetBundle(OPERATIONAL_SCHEMA_VERSION, tuple(targets))

    vpc_address = "module.network.aws_vpc.this"
    vpc = reference(vpc_address)
    route_address = "module.network.aws_route_table.private"
    route = reference(route_address)
    subnet_addresses = tuple(f"module.network.aws_subnet.private[{index}]" for index in range(2))
    subnets = [reference(address) for address in subnet_addresses]
    group_address = "module.network.aws_security_group.endpoints"
    group = reference(group_address)

    def ec2(
        address: str,
        kind: str,
        method: str,
        argument: str,
        result: str,
        identity_key: str,
        name: str,
        expectations: dict[str, object],
        extra_tags: dict[str, object] | None = None,
        cost: bool = False,
    ) -> None:
        identity = reference(address)
        read = probe(
            address,
            kind,
            "ec2",
            method,
            {argument: [identity]},
            result,
            identity_key,
            identity,
            ("NextToken", "NextToken"),
        )
        target(
            read,
            assertion(
                "OWNERSHIP",
                read,
                {
                    "Tags": {**tags, "Name": name, **(extra_tags or {})},
                },
            ),
            (assertion("CONFIGURATION", read, expectations),),
            cost=cost,
        )

    ec2(
        vpc_address,
        "aws_vpc",
        "describe_vpcs",
        "VpcIds",
        "Vpcs",
        "VpcId",
        "enterprise-ai-sandbox",
        {"CidrBlock": "10.60.0.0/16", "State": "available"},
    )
    for index, address in enumerate(subnet_addresses):
        ec2(
            address,
            "aws_subnet",
            "describe_subnets",
            "SubnetIds",
            "Subnets",
            "SubnetId",
            f"enterprise-ai-sandbox-private-{index + 1}",
            {
                "VpcId": vpc,
                "CidrBlock": f"10.60.{10 + index}.0/24",
                "AvailabilityZone": "ap-southeast-1" + ("a" if index == 0 else "b"),
                "MapPublicIpOnLaunch": False,
            },
            {"Tier": "private"},
        )
    ec2(
        "module.network.aws_default_security_group.restricted",
        "aws_default_security_group",
        "describe_security_groups",
        "GroupIds",
        "SecurityGroups",
        "GroupId",
        "enterprise-ai-sandbox-default-restricted",
        {"VpcId": vpc, "IpPermissions": [], "IpPermissionsEgress": []},
    )
    ec2(
        group_address,
        "aws_security_group",
        "describe_security_groups",
        "GroupIds",
        "SecurityGroups",
        "GroupId",
        "enterprise-ai-sandbox-vpc-endpoints",
        {
            "VpcId": vpc,
            "IpPermissionsEgress": [],
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [
                        {
                            "CidrIp": "10.60.0.0/16",
                            "Description": "TLS from the exact sandbox VPC CIDR",
                        }
                    ],
                    "Ipv6Ranges": [],
                    "PrefixListIds": [],
                    "UserIdGroupPairs": [],
                }
            ],
        },
    )
    gateway = {"S3": "s3", "DynamoDB": "dynamodb"}
    interface = {
        "ECR API": "ecr.api",
        "ECR DKR": "ecr.dkr",
        "EKS": "eks",
        "STS": "sts",
        "CloudWatch Logs": "logs",
        "KMS": "kms",
        "Secrets Manager": "secretsmanager",
        "Bedrock Runtime": "bedrock-runtime",
    }
    routes: list[dict[str, object]] = [
        {
            "DestinationCidrBlock": "10.60.0.0/16",
            "GatewayId": "local",
            "Origin": "CreateRouteTable",
            "State": "active",
        }
    ]
    for label in gateway:
        endpoint_address = f'module.network.aws_vpc_endpoint.gateway["{label}"]'
        routes.append(
            {
                "DestinationPrefixListId": reference(endpoint_address, "prefix_list_id"),
                "GatewayId": reference(endpoint_address),
                "Origin": "CreateRoute",
                "State": "active",
            }
        )
    ec2(
        route_address,
        "aws_route_table",
        "describe_route_tables",
        "RouteTableIds",
        "RouteTables",
        "RouteTableId",
        "enterprise-ai-sandbox-private",
        {"VpcId": vpc, "Routes.@unordered": routes},
    )
    associations = [
        {
            "Main": False,
            "RouteTableAssociationId": reference(
                f"module.network.aws_route_table_association.private[{index}]"
            ),
            "RouteTableId": route,
            "SubnetId": subnets[index],
            "AssociationState": {"State": "associated"},
        }
        for index in range(2)
    ]
    for index in range(2):
        address = f"module.network.aws_route_table_association.private[{index}]"
        read = probe(
            address,
            "aws_route_table_association",
            "ec2",
            "describe_route_tables",
            {"RouteTableIds": [route]},
            "RouteTables",
            "RouteTableId",
            route,
            ("NextToken", "NextToken"),
        )
        target(
            read,
            assertion(
                "OWNERSHIP",
                read,
                {
                    "Tags": {**tags, "Name": "enterprise-ai-sandbox-private"},
                },
            ),
            (assertion("CONFIGURATION", read, {"Associations.@unordered": associations}),),
        )
    for family, labels in (("gateway", gateway), ("interface", interface)):
        for label, service in labels.items():
            address = f'module.network.aws_vpc_endpoint.{family}["{label}"]'
            expectations = {
                "VpcId": vpc,
                "State": "available",
                "VpcEndpointType": "Gateway" if family == "gateway" else "Interface",
                "ServiceName": f"com.amazonaws.{region}.{service}",
                "PolicyDocument.@diagnostic_policy_sha256": {
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ],
                },
            }
            if family == "gateway":
                expectations["RouteTableIds"] = [route]
            else:
                expectations.update(
                    {
                        "PrivateDnsEnabled": True,
                        "SubnetIds.@unordered": subnets,
                        "Groups.@unordered": [
                            {
                                "GroupId": group,
                                "GroupName": "enterprise-ai-sandbox-vpc-endpoints",
                            }
                        ],
                    }
                )
            ec2(
                address,
                "aws_vpc_endpoint",
                "describe_vpc_endpoints",
                "VpcEndpointIds",
                "VpcEndpoints",
                "VpcEndpointId",
                "enterprise-ai-sandbox-" + "-".join(label.lower().split()),
                expectations,
                cost=family == "interface",
            )

    for name in ("runtime", "ingestion", "opensearch_administrator", "github_oidc"):
        role_name = (
            "enterprise-ai-sandbox-opensearch-admin"
            if name == "opensearch_administrator"
            else "enterprise-ai-platform-sandbox-github-oidc"
            if name == "github_oidc"
            else "enterprise-ai-sandbox-" + name
        )
        address = "module.iam.aws_iam_role." + name
        read = probe(
            address,
            "aws_iam_role",
            "iam",
            "get_role",
            {"RoleName": role_name},
            "Role",
            "Arn",
            f"arn:aws:iam::{account}:role/{role_name}",
        )
        target(
            read,
            assertion("OWNERSHIP", read, {"Tags": tags}),
            (
                assertion(
                    "CONFIGURATION",
                    read,
                    {
                        "Arn": f"arn:aws:iam::{account}:role/{role_name}",
                        "AssumeRolePolicyDocument.@diagnostic_policy_sha256": policies[
                            name + "_trust"
                        ],
                    },
                ),
            ),
        )
        if name in {"runtime", "ingestion"}:
            address = "module.iam.aws_iam_role_policy." + name
            policy = probe(
                address,
                "aws_iam_role_policy",
                "iam",
                "get_role_policy",
                {"RoleName": role_name, "PolicyName": role_name},
                "",
                "PolicyName",
                role_name,
            )
            owner = probe(
                address,
                "aws_iam_role_policy",
                "iam",
                "get_role",
                {"RoleName": role_name},
                "Role",
                "RoleName",
                role_name,
            )
            target(
                policy,
                assertion("OWNERSHIP", owner, {"Tags": tags}),
                (
                    assertion(
                        "CONFIGURATION",
                        policy,
                        {
                            "RoleName": role_name,
                            "PolicyDocument.@diagnostic_policy_sha256": policies[name],
                        },
                    ),
                ),
            )
    repository_name = "enterprise-ai/sandbox/api"
    repository_arn = f"arn:aws:ecr:{region}:{account}:repository/{repository_name}"
    for kind, name in (
        ("aws_ecr_repository", "this"),
        ("aws_ecr_lifecycle_policy", "retain_exact_count"),
    ):
        address = "module.ecr." + kind + "." + name
        read = probe(
            address,
            kind,
            "ecr",
            "describe_repositories",
            {"repositoryNames": [repository_name], "registryId": account},
            "repositories",
            "repositoryArn",
            repository_arn,
        )
        owner = probe(
            address,
            kind,
            "ecr",
            "list_tags_for_resource",
            {"resourceArn": repository_arn},
            "",
            "",
            repository_arn,
        )
        checks = (
            assertion(
                "CONFIGURATION",
                read,
                {
                    "imageTagMutability": "IMMUTABLE",
                    "imageScanningConfiguration.scanOnPush": True,
                    "encryptionConfiguration.encryptionType": "KMS",
                    "encryptionConfiguration.kmsKey": key_arn,
                },
            ),
        )
        if kind == "aws_ecr_lifecycle_policy":
            policy = probe(
                address,
                kind,
                "ecr",
                "get_lifecycle_policy",
                {"repositoryName": repository_name, "registryId": account},
                "",
                "",
                repository_name,
            )
            checks = (
                assertion(
                    "CONFIGURATION",
                    policy,
                    {
                        "lifecyclePolicyText.@json": {
                            "rules": [
                                {
                                    "rulePriority": 1,
                                    "description": "Retain exactly the ten most recent images",
                                    "selection": {
                                        "tagStatus": "any",
                                        "countType": "imageCountMoreThan",
                                        "countNumber": 10,
                                    },
                                    "action": {"type": "expire"},
                                }
                            ]
                        }
                    },
                ),
            )
        target(
            read,
            assertion("OWNERSHIP", owner, {"tags": tags}),
            checks,
            cost=kind == "aws_ecr_repository",
        )

    domain_name = "enterprise-ai-sandbox"
    domain_arn = f"arn:aws:es:{region}:{account}:domain/{domain_name}"
    log_options: dict[str, object] = {}
    for name, suffix, log_type in (
        ("application", "application-logs", "ES_APPLICATION_LOGS"),
        ("audit", "audit-logs", "AUDIT_LOGS"),
        ("index_slow", "index-slow-logs", "INDEX_SLOW_LOGS"),
        ("search_slow", "search-slow-logs", "SEARCH_SLOW_LOGS"),
    ):
        log_name = f"/aws/OpenSearchService/domains/{domain_name}/{suffix}"
        arn = f"arn:aws:logs:{region}:{account}:log-group:{log_name}"
        address = f'module.opensearch.aws_cloudwatch_log_group.this["{name}"]'
        read = probe(
            address,
            "aws_cloudwatch_log_group",
            "logs",
            "describe_log_groups",
            {"logGroupNamePrefix": log_name},
            "logGroups",
            "logGroupArn",
            arn,
            ("nextToken", "nextToken"),
        )
        owner = probe(
            address,
            "aws_cloudwatch_log_group",
            "logs",
            "list_tags_for_resource",
            {"resourceArn": arn},
            "",
            "",
            arn,
        )
        target(
            read,
            assertion("OWNERSHIP", owner, {"tags": tags}),
            (assertion("CONFIGURATION", read, {"retentionInDays": 30, "kmsKeyId": key_arn}),),
            cost=True,
        )
        log_options[log_type] = {"Enabled": True, "CloudWatchLogsLogGroupArn": arn}
    address = "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch"
    name = "enterprise-ai-sandbox-opensearch-log-delivery"
    read = probe(
        address,
        "aws_cloudwatch_log_resource_policy",
        "logs",
        "describe_resource_policies",
        {},
        "resourcePolicies",
        "policyName",
        name,
        ("nextToken", "nextToken"),
    )
    # Diagnostic-only structural ownership: exact source policy and exact name, no tag fiction.
    target(
        read,
        assertion(
            "SOURCE_OWNERSHIP",
            read,
            {
                "policyName": name,
                "policyDocument.@diagnostic_policy_sha256": policies["log_delivery"],
            },
        ),
        (
            assertion(
                "CONFIGURATION",
                read,
                {
                    "policyDocument.@diagnostic_policy_sha256": policies["log_delivery"],
                },
            ),
        ),
    )
    address = "module.opensearch.aws_opensearch_domain.this"
    read = probe(
        address,
        "aws_opensearch_domain",
        "opensearch",
        "describe_domain",
        {"DomainName": domain_name},
        "DomainStatus",
        "ARN",
        domain_arn,
    )
    owner = probe(
        address,
        "aws_opensearch_domain",
        "opensearch",
        "list_tags",
        {"ARN": domain_arn},
        "",
        "",
        domain_arn,
    )
    target(
        read,
        assertion("OWNERSHIP", owner, {"TagList": tags}),
        (
            assertion(
                "CONFIGURATION",
                read,
                {
                    "Created": True,
                    "Deleted": False,
                    "Processing": False,
                    "VPCOptions.VPCId": vpc,
                    "VPCOptions.SubnetIds": [subnets[0]],
                    "VPCOptions.SecurityGroupIds": [group],
                    "EngineVersion": "OpenSearch_2.19",
                    "EncryptionAtRestOptions.Enabled": True,
                    "EncryptionAtRestOptions.KmsKeyId.@kms_identity": key_id,
                    "NodeToNodeEncryptionOptions.Enabled": True,
                    "DomainEndpointOptions.EnforceHTTPS": True,
                    "DomainEndpointOptions.TLSSecurityPolicy": "Policy-Min-TLS-1-2-2019-07",
                    "AdvancedSecurityOptions.Enabled": True,
                    "AdvancedSecurityOptions.InternalUserDatabaseEnabled": False,
                    "LogPublishingOptions": log_options,
                    "AccessPolicies.@diagnostic_policy_sha256": policies["domain_access"],
                    "ClusterConfig.InstanceType": "t3.small.search",
                    "ClusterConfig.InstanceCount": 1,
                    "ClusterConfig.DedicatedMasterEnabled": False,
                    "ClusterConfig.ZoneAwarenessEnabled": False,
                    "EBSOptions.EBSEnabled": True,
                    "EBSOptions.VolumeType": "gp3",
                    "EBSOptions.VolumeSize": 10,
                },
            ),
        ),
        cost=True,
    )
    return NativeTargetBundle(OPERATIONAL_SCHEMA_VERSION, tuple(targets))
