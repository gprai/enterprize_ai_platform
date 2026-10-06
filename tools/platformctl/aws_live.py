"""Explicit, injectable live-AWS identity and bounded inventory adapter."""

from __future__ import annotations

import importlib
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from typing import NoReturn, Protocol, cast

from .aws_inventory import (
    DIAGNOSTIC_LIMITS,
    PREREQUISITE_CORRECTION_LIMITS,
    PREREQUISITE_LIMITS,
    PREREQUISITE_LOG_ACTIONS,
    PREREQUISITE_LOG_NAMES,
    PREREQUISITE_POLICY,
    PREREQUISITE_ROLES,
    PREREQUISITE_ROUTES,
    PUBLIC_CHARGING_PAGES,
    RESOLUTION_BILLING_END,
    RESOLUTION_BILLING_START,
    RESOLUTION_EVENTS_END,
    RESOLUTION_EVENTS_START,
    RESOLUTION_FOLLOWUP_EVIDENCE_SHA256,
    RESOLUTION_FOLLOWUP_IDENTITY_SHA256,
    RESOLUTION_LIMITS,
    AwsInventoryProvider,
    InventoryResource,
    NativeReadSpec,
    NativeScanBundle,
    NativeTarget,
    ServiceIdentifier,
)
from .contracts import (
    APPROVED_AWS_ACCOUNT_ID,
    APPROVED_AWS_REGION,
    APPROVED_CALLER_ARN,
    Action,
    ContractError,
    VerifiedExecutionContext,
    parse_utc_timestamp,
    stable_cleanup_tags,
    validate_aws_account_id,
    validate_aws_region,
)
from .lifecycle_io import (
    canonical_json_bytes,
    decode_json_strict,
    decode_operational_record,
    sha256_bytes,
)
from .lifecycle_models import (
    OPERATIONAL_SCHEMA_VERSION,
    InventoryEntry,
    InventoryResult,
    Outcome,
    PurgeInventoryV2,
    PurgeItem,
)
from .operation_state import OperationLedger

W6_004_MAX_NATIVE_DISCOVERY_REQUESTS = 160
W6_004_MAX_BILLING_REQUESTS = 6


def fetch_public_charging_pages() -> tuple[list[dict[str, object]], int, float]:
    """Explicit anonymous transport adapter; bodies stay in the calling process only.

    Like the SDK factory, transport is loaded only at this explicit live boundary.
    No SDK session, credential provider, proxy or ambient HTTP configuration is used.
    The caller must reserve its single-use operation directory before entering.
    """
    import ssl

    transport = importlib.import_module("http.client")
    start = time.monotonic()
    rows: list[dict[str, object]] = []
    requests = 0
    for url in PUBLIC_CHARGING_PAGES:
        remaining = 300 - (time.monotonic() - start)
        if remaining <= 0:
            break
        # Fixed literal HTTPS URLs only: no caller-supplied URL or endpoint override.
        host, path = url.removeprefix("https://").split("/", 1)
        if not url.startswith("https://") or host not in {
            "aws.amazon.com",
            "docs.aws.amazon.com",
        }:
            raise ContractError("PUBLIC_PRICING_EXACT_HOST_REQUIRED")
        row: dict[str, object] = {"url": url, "status": "UNAVAILABLE"}
        connection = transport.HTTPSConnection(
            host, timeout=min(30, remaining), context=ssl.create_default_context()
        )
        requests += 1
        try:
            connection.request("GET", "/" + path, headers={"Accept-Encoding": "identity"})
            remaining = 300 - (time.monotonic() - start)
            if remaining <= 0:
                raise TimeoutError
            if connection.sock is not None:
                connection.sock.settimeout(min(30, remaining))
            response = connection.getresponse()
            row["http_status"] = response.status
            if response.status != 200:
                row["status"] = (
                    "REDIRECT_NOT_FOLLOWED" if 300 <= response.status < 400 else "HTTP_UNAVAILABLE"
                )
            elif response.getheader("Content-Encoding", "identity") != "identity":
                row["status"] = "ENCODING_UNSUPPORTED"
            else:
                body = bytearray()
                while len(body) < 2097152:
                    remaining = 300 - (time.monotonic() - start)
                    if remaining <= 0:
                        raise TimeoutError
                    if connection.sock is not None:
                        connection.sock.settimeout(min(30, remaining))
                    chunk = response.read1(min(65536, 2097152 - len(body)))
                    if not chunk:
                        break
                    body.extend(chunk)
                if len(body) == 2097152:
                    row["status"] = "RESPONSE_LIMIT_REACHED_NOT_ACCEPTED"
                else:
                    row.update(status="RETRIEVED_APPLICABILITY_UNVERIFIED", body=bytes(body))
        except (OSError, transport.HTTPException, ValueError):
            row["status"] = "TRANSPORT_OR_CONTENT_UNAVAILABLE"
        finally:
            connection.close()
        rows.append(row)
    return rows, requests, time.monotonic() - start


def safe_context_names(keys: Sequence[str]) -> list[str]:
    """Report recognized key names, never arbitrary strings originating in policy input."""
    known = {
        "aws:RequestedRegion",
        "aws:PrincipalArn",
        "aws:PrincipalAccount",
        "aws:username",
        "aws:CurrentTime",
        "aws:SecureTransport",
        "aws:TagKeys",
        "aws:PrincipalOrgID",
        "aws:MultiFactorAuthPresent",
        "aws:MultiFactorAuthAge",
        "aws:PrincipalType",
        "aws:SourceAccount",
        "aws:SourceArn",
        "aws:SourceVpc",
        "aws:SourceVpce",
        "aws:SourceIp",
        "kms:ViaService",
        "kms:EncryptionContext:aws:logs:arn",
    }
    known.update(
        f"aws:{kind}/{tag}"
        for kind in ("RequestTag", "ResourceTag", "PrincipalTag")
        for tag in ("ExpiresAt", "Project", "Environment", "Owner", "CostCenter", "ManagedBy")
    )
    return sorted({key if key in known else "UNCLASSIFIED_CONTEXT_KEY_REDACTED" for key in keys})


def normalize_simulation_results(
    rows: Sequence[Mapping[str, object]], action: str, targets: Sequence[str], *, complete: bool
) -> dict[str, object]:
    """Normalize the installed IAM action/resource response without inventing decisions."""
    decisions = {"allowed", "implicitDeny", "explicitDeny"}
    findings: dict[str, dict[str, object]] = {}
    issues: set[str] = set()
    context: set[str] = set()
    if not targets or len(set(targets)) != len(targets):
        raise ContractError("SIMULATION_TARGETS_INVALID")

    def missing(value: object) -> list[str]:
        if not isinstance(value, list) or any(not isinstance(key, str) for key in value):
            issues.add("MALFORMED_CONTEXT")
            return []
        return safe_context_names(cast(list[str], value))

    for row in rows:
        if row.get("EvalActionName") != action:
            issues.add("UNEXPECTED_ACTION")
            continue
        aggregate = row.get("EvalDecision")
        if not isinstance(aggregate, str) or aggregate not in decisions:
            issues.add("MALFORMED_AGGREGATE")
            aggregate = None
        inherited = missing(row.get("MissingContextValues", []))
        context.update(inherited)
        specific = row.get("ResourceSpecificResults")
        if specific is None and len(targets) == 1 and row.get("EvalResourceName") == targets[0]:
            specific = [row]
        if not isinstance(specific, list) or not specific:
            issues.add("RESOURCE_RESULTS_UNAVAILABLE")
            continue
        for value in specific:
            if not isinstance(value, dict):
                issues.add("MALFORMED_RESOURCE_RESULT")
                continue
            resource = value.get("EvalResourceName")
            if not isinstance(resource, str) or resource not in targets:
                issues.add("UNEXPECTED_RESOURCE")
                continue
            if resource in findings:
                issues.add("DUPLICATE_RESOURCE")
                continue
            decision = value.get("EvalResourceDecision", value.get("EvalDecision"))
            if not isinstance(decision, str) or decision not in decisions:
                issues.add("MALFORMED_RESOURCE_DECISION")
                decision = None
            keys = sorted(set(inherited + missing(value.get("MissingContextValues", []))))
            context.update(keys)
            details: dict[str, object] = {}
            policy_decisions = value.get("EvalDecisionDetails", row.get("EvalDecisionDetails"))
            if policy_decisions is not None:
                if not isinstance(policy_decisions, dict) or any(
                    key
                    not in {
                        "IdentityPolicy",
                        "ResourcePolicy",
                        "PermissionsBoundary",
                        "Organizations",
                    }
                    or not isinstance(val, str)
                    or val not in decisions
                    for key, val in policy_decisions.items()
                ):
                    issues.add("UNCLASSIFIED_DECISION_MAP")
                else:
                    details["EvalDecisionDetails"] = policy_decisions
            for source, fields in (
                ("PermissionsBoundaryDecisionDetail", ("AllowedByPermissionsBoundary",)),
                ("OrganizationsDecisionDetail", ("AllowedByOrganizations",)),
            ):
                detail = value.get(source, row.get(source))
                if detail is None:
                    continue
                if not isinstance(detail, dict) or any(
                    type(detail.get(k)) is not bool for k in fields
                ):
                    issues.add("MALFORMED_DECISION_DETAIL")
                else:
                    details[source] = {k: detail[k] for k in fields}
            findings[resource] = {
                "resource": resource,
                "decision": decision,
                "action_aggregate": aggregate,
                "missing_context": keys,
                "decision_details": details,
                "assessment": "INDETERMINATE"
                if keys or decision is None
                else ("ALLOWED" if decision == "allowed" else "DENIED"),
            }
    if not complete:
        issues.add("ENUMERATION_INCOMPLETE")
    if set(findings) != set(targets):
        issues.add("MISSING_RESOURCES")
    for target in targets:
        findings.setdefault(
            target,
            {
                "resource": target,
                "decision": None,
                "action_aggregate": None,
                "missing_context": [],
                "decision_details": {},
                "assessment": "INDETERMINATE",
                "evidence": "RESOURCE_RESULT_UNAVAILABLE",
            },
        )
    assessment = "INDETERMINATE"
    if not issues and not context:
        assessment = (
            "ALLOWED" if all(v["decision"] == "allowed" for v in findings.values()) else "DENIED"
        )
    return {
        "action": action,
        "findings": [findings[target] for target in targets if target in findings],
        "coverage_complete": not issues,
        "issues": sorted(issues),
        "missing_context": sorted(context),
        "assessment": assessment,
        "allowed": True if assessment == "ALLOWED" else False if assessment == "DENIED" else None,
        "live_authorization_guarantee": False,
        "limitations": [
            "SIMULATOR_NOT_LIVE_SERVICE_AUTHORIZATION",
            "UNMODELED_SESSION_OR_ORGANIZATION_CONTROLS",
        ],
    }


def resolution_policy_differences(
    expected: object, observed: object, *, approved_default_endpoint: bool = False
) -> dict[str, object]:
    """Compare policy semantics privately; output paths/categories, never policy values."""

    def normalize(value: object, field: str = "") -> object:
        if isinstance(value, dict):
            return {key: normalize(child, key) for key, child in value.items()}
        if field in {"Action", "NotAction", "Resource", "NotResource", "AWS", "Service"}:
            values = value if isinstance(value, list) else [value]
            if any(not isinstance(item, str) for item in values):
                raise ContractError("RESOLUTION_POLICY_FIELD_MALFORMED")
            return sorted(set(cast(list[str], values)))
        if isinstance(value, list):
            children = [normalize(child) for child in value]
            return sorted(children, key=canonical_json_bytes)
        if value is None or type(value) not in {str, bool, int}:
            raise ContractError("RESOLUTION_POLICY_FIELD_MALFORMED")
        return value

    if approved_default_endpoint and _default_endpoint_policy(expected):
        if _default_endpoint_policy(observed):
            observed = expected
    documents: list[dict[str, object]] = []
    for raw in (expected, observed):
        value = decode_json_strict(raw.encode()) if isinstance(raw, str) else raw
        if not isinstance(value, dict) or set(value) - {"Version", "Id", "Statement"}:
            raise ContractError("RESOLUTION_POLICY_DOCUMENT_MALFORMED")
        statements = value.get("Statement")
        if isinstance(statements, dict):
            statements = [statements]
        if not isinstance(statements, list) or not statements:
            raise ContractError("RESOLUTION_POLICY_STATEMENTS_MALFORMED")
        if any(
            not isinstance(row, dict)
            or row.get("Effect") not in {"Allow", "Deny"}
            or set(row)
            - {
                "Sid",
                "Effect",
                "Action",
                "NotAction",
                "Resource",
                "NotResource",
                "Principal",
                "NotPrincipal",
                "Condition",
            }
            for row in statements
        ):
            raise ContractError("RESOLUTION_POLICY_STATEMENT_MALFORMED")
        documents.append({**value, "Statement": statements})
    before, after = (
        normalize(
            {
                **{key: child for key, child in value.items() if key not in {"Id", "Statement"}},
                "Statement": [
                    {key: child for key, child in row.items() if key != "Sid"}
                    for row in cast(list[dict[str, object]], value["Statement"])
                ],
            }
        )
        for value in documents
    )
    differences: list[dict[str, str]] = []
    safe_keys = {
        "Version",
        "Statement",
        "Effect",
        "Action",
        "NotAction",
        "Resource",
        "NotResource",
        "Principal",
        "NotPrincipal",
        "Condition",
        "AWS",
        "Service",
        "StringEquals",
        "StringLike",
        "ArnEquals",
        "ArnLike",
        "Bool",
        "Null",
        "aws:SourceAccount",
        "aws:SourceArn",
        "aws:PrincipalArn",
        "aws:SourceVpce",
    }

    def compare(left: object, right: object, path: str) -> None:
        if type(left) is not type(right):
            differences.append({"path": path, "category": "TYPE_DIFFERENCE"})
        elif isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(left.keys() | right.keys()):
                child_path = path + "." + (key if key in safe_keys else "<unreviewed-field>")
                if key not in left or key not in right:
                    differences.append({"path": child_path, "category": "MISSING_FIELD"})
                else:
                    compare(left[key], right[key], child_path)
        elif isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                differences.append({"path": path, "category": "MEMBER_COUNT_DIFFERENCE"})
            for index, (first, second) in enumerate(zip(left, right, strict=False)):
                compare(first, second, f"{path}[{index}]")
        elif left != right:
            differences.append({"path": path, "category": "SEMANTIC_VALUE_DIFFERENCE"})

    compare(before, after, "PolicyDocument")
    return {
        "classification": "SEMANTIC_DIFFERENCE" if differences else "SEMANTIC_MATCH",
        "differences": differences,
        "raw_values_retained": False,
        "representation_only_difference": not differences and documents[0] != documents[1],
    }


def _diagnostic_url_allowed(value: object, hosts: set[str], *, endpoint: bool = False) -> bool:
    """Match exact HTTPS authorities, without normalizing ambiguous URL syntax."""
    if (
        not isinstance(value, str)
        or not value.startswith("https://")
        or any(ord(character) <= 32 or ord(character) >= 127 for character in value)
        or "\\" in value
        or "#" in value
    ):
        return False
    remainder = value[len("https://") :]
    authority = remainder.partition("/")[0].partition("?")[0]
    if authority not in {name + port for name in hosts for port in ("", ":443")}:
        return False
    return not endpoint or remainder[len(authority) :] in {"", "/"}


class AwsClient(Protocol):
    """Minimal dynamic client protocol used by injected test doubles."""

    def get_caller_identity(self) -> Mapping[str, object]:
        """Return STS caller identity."""
        ...


class AwsSession(Protocol):
    """Minimal boto3 Session surface retained behind the live adapter."""

    def client(self, service_name: str, *, region_name: str, config: object) -> object:
        """Create one approved service client."""
        ...


class AwsSessionFactory(Protocol):
    """Typed dynamic constructor for boto3.Session."""

    def __call__(self, *, profile_name: str, region_name: str) -> AwsSession:
        """Create an external-profile session."""
        ...


class NativeServiceLister(Protocol):
    """Service-specific inventory boundary; implementations must not fetch secrets."""

    def list_resources(self, service: ServiceIdentifier) -> Sequence[InventoryResource]:
        """Return bounded native inventory for one approved service."""
        ...


class CompleteNativeServiceLister:
    """Require an explicit bounded discoverer for every governed AWS service."""

    def __init__(
        self,
        discoverers: Mapping[ServiceIdentifier, Callable[[], Sequence[InventoryResource]]],
    ) -> None:
        if set(discoverers) != set(ServiceIdentifier):
            raise ContractError("native inventory coverage must include every approved service")
        self._discoverers = dict(discoverers)

    def list_resources(self, service: ServiceIdentifier) -> Sequence[InventoryResource]:
        """Return stable deduplicated inventory from one explicit service discoverer."""
        resources = self._discoverers[service]()
        identities = [resource.resource_id for resource in resources]
        if not all(identities) or len(identities) != len(set(identities)):
            raise ContractError("native inventory contains blank or duplicate identities")
        return tuple(sorted(resources, key=lambda resource: resource.resource_id))


@dataclass(frozen=True)
class VerifiedAwsIdentity:
    """Non-secret account, region, and caller identity."""

    account_id: str
    region: str
    caller_arn: str
    principal_class: str


class Boto3AwsInventoryProvider(AwsInventoryProvider):
    """Live adapter enabled only by a separately approved owner command."""

    def __init__(
        self,
        *,
        client_factory: Callable[[str, str], object],
        native_lister: NativeServiceLister | None,
        region: str,
        account_id: str,
        caller_arn: str,
        profile: str = "default",
    ) -> None:
        self._client_factory = client_factory
        self._native_lister = native_lister
        self._region = validate_aws_region(region)
        self._account_id = validate_aws_account_id(account_id)
        self._caller_arn = caller_arn
        if (
            self._region != APPROVED_AWS_REGION
            or self._account_id != APPROVED_AWS_ACCOUNT_ID
            or self._caller_arn != APPROVED_CALLER_ARN
        ):
            raise ContractError("AWS live adapter identity is outside the approved boundary")
        if profile != "default":
            raise ContractError("AWS profile must be exactly default")
        self._profile = profile

    @classmethod
    def from_profile(
        cls,
        *,
        native_lister: NativeServiceLister | None,
        profile: str,
        region: str,
        account_id: str,
        caller_arn: str,
        diagnostic_only: bool = False,
    ) -> Boto3AwsInventoryProvider:
        """Create a session from the exact owner-approved external profile."""
        if profile != "default":
            raise ContractError("AWS profile must be exactly default")
        reject_ambient_aws_overrides()
        module = importlib.import_module("boto3")
        session_attribute = getattr(module, "Session", None)
        if session_attribute is None:
            raise ContractError("boto3 Session is unavailable")
        session_factory = cast(AwsSessionFactory, session_attribute)
        session = session_factory(profile_name=profile, region_name=region)
        if diagnostic_only:
            scope_reader = getattr(getattr(session, "_session", None), "get_scoped_config", None)
            if not callable(scope_reader):
                raise ContractError("DIAGNOSTIC_PROFILE_INSPECTION_UNAVAILABLE")
            scoped = scope_reader()
            if (
                not isinstance(scoped, dict)
                or set(scoped)
                - {
                    "aws_access_key_id",
                    "aws_secret_access_key",
                    "aws_session_token",
                    "region",
                    "output",
                }
                or not isinstance(scoped.get("output", "json"), str)
                or scoped.get("output", "json")
                not in {"json", "text", "table", "yaml", "yaml-stream"}
                or any(
                    not isinstance(scoped.get(key), str) or not scoped[key]
                    for key in (
                        "aws_access_key_id",
                        "aws_secret_access_key",
                    )
                )
                or scoped.get("region", region) != region
            ):
                raise ContractError("DIAGNOSTIC_STATIC_OWNER_PROFILE_REQUIRED")
        config_factory = importlib.import_module("botocore.config").Config
        sdk_config = config_factory(
            connect_timeout=10,
            read_timeout=30,
            retries={"mode": "standard", "total_max_attempts": 1},
        )

        def client_factory(service: str, requested_region: str) -> object:
            client_config = sdk_config
            if diagnostic_only and service == "dynamodb":
                # ResourceArn can select an account-based host before any HTTP response.
                # Keep diagnostic requests on the existing exact regional allowlist.
                client_config = sdk_config.merge(
                    config_factory(account_id_endpoint_mode="disabled")
                )
            return session.client(service, region_name=requested_region, config=client_config)

        return cls(
            client_factory=client_factory,
            native_lister=native_lister,
            region=region,
            account_id=account_id,
            caller_arn=caller_arn,
            profile=profile,
        )

    def verify_identity(self) -> VerifiedAwsIdentity:
        """Stop on any account, Region, or exact caller mismatch."""
        client = cast(AwsClient, self._client_factory("sts", self._region))
        result = client.get_caller_identity()
        account = result.get("Account")
        arn = result.get("Arn")
        if account != self._account_id or arn != self._caller_arn:
            raise ContractError("AWS caller identity does not match the approved boundary")
        return VerifiedAwsIdentity(
            account_id=self._account_id,
            region=self._region,
            caller_arn=self._caller_arn,
            principal_class="IAM user",
        )

    def bounded_reader(self) -> BoundedNativeReader:
        """Use the same identity-bound session for independently checked reads."""
        return BoundedNativeReader(self, self._client_factory)

    def bounded_purge(self) -> S3PurgeAdapter:
        """Use the same session without exposing an unrestricted client to orchestration."""
        return S3PurgeAdapter(self, self._client_factory)

    def discover(self, bundle: NativeScanBundle) -> tuple[tuple[str, str], ...]:
        """Enumerate project-tagged resources independently of the Terraform address list."""
        return discover_project_resources(self, self._client_factory, bundle)

    def list_tagged_resources(
        self, required_tags: Mapping[str, str]
    ) -> Sequence[InventoryResource]:
        """Delegate to the approved native implementation after identity validation."""
        self.verify_identity()
        if self._native_lister is None:
            raise ContractError("COMPLETE_NATIVE_DISCOVERY_REQUIRED")
        resources: list[InventoryResource] = []
        for service in ServiceIdentifier:
            for resource in self._native_lister.list_resources(service):
                if all(resource.tags.get(key) == value for key, value in required_tags.items()):
                    resources.append(resource)
        return tuple(sorted(resources, key=lambda item: (item.service.value, item.resource_id)))

    def list_service_resources(self, service: ServiceIdentifier) -> Sequence[InventoryResource]:
        """Run one exact native-service inventory call with no secret-value retrieval."""
        self.verify_identity()
        if self._native_lister is None:
            raise ContractError("COMPLETE_NATIVE_DISCOVERY_REQUIRED")
        return tuple(
            sorted(
                self._native_lister.list_resources(service),
                key=lambda item: item.resource_id,
            )
        )


def reject_ambient_aws_overrides() -> None:
    """Do not print override names or values that might disclose identity material."""
    permitted = {"AWS_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION", "AWS_EC2_METADATA_DISABLED"}
    if any(key.upper().startswith("AWS_") and key.upper() not in permitted for key in os.environ):
        raise ContractError("AWS_AMBIENT_OVERRIDE_PROHIBITED")
    if os.environ.get("AWS_PROFILE", "default") != "default" or any(
        os.environ.get(key, APPROVED_AWS_REGION) != APPROVED_AWS_REGION
        for key in ("AWS_REGION", "AWS_DEFAULT_REGION")
    ):
        raise ContractError("AWS_AMBIENT_ROUTING_MISMATCH")


def process_cost_environment(environment: Mapping[str, str]) -> dict[str, str]:
    """Read a process-scoped pricing credential without logging or storing its value."""
    key = os.environ.get("INFRACOST_API_KEY")
    if not key or any(character in key for character in ("\x00", "\r", "\n")):
        raise ContractError("PROCESS_PRICING_CREDENTIAL_UNAVAILABLE")
    permitted = {"PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"}
    return {
        **{name: value for name, value in environment.items() if name.upper() in permitted},
        "INFRACOST_API_KEY": key,
    }


_READ_METHODS: Mapping[str, frozenset[str]] = {
    "ec2": frozenset(
        {
            "describe_vpcs",
            "describe_subnets",
            "describe_route_tables",
            "describe_security_groups",
            "describe_vpc_endpoints",
            "describe_network_interfaces",
            "describe_volumes",
            "describe_addresses",
        }
    ),
    "logs": frozenset(
        {"describe_log_groups", "describe_resource_policies", "list_tags_for_resource"}
    ),
    "cloudwatch": frozenset({"describe_alarms", "list_tags_for_resource"}),
    "opensearch": frozenset({"describe_domain", "list_domain_names", "list_tags"}),
    "kms": frozenset(
        {
            "describe_key",
            "list_keys",
            "list_aliases",
            "list_resource_tags",
            "get_key_rotation_status",
            "get_key_policy",
        }
    ),
    "iam": frozenset(
        {
            "get_role",
            "get_role_policy",
            "get_policy",
            "get_policy_version",
            "list_roles",
            "list_policies",
            "list_role_tags",
            "list_policy_tags",
            "list_attached_role_policies",
            "list_role_policies",
        }
    ),
    "ecr": frozenset(
        {
            "describe_repositories",
            "describe_images",
            "list_tags_for_resource",
            "get_lifecycle_policy",
        }
    ),
    "s3": frozenset(
        {
            "head_bucket",
            "list_buckets",
            "get_bucket_location",
            "get_bucket_tagging",
            "get_public_access_block",
            "get_bucket_encryption",
            "get_bucket_versioning",
            "get_bucket_policy_status",
            "get_bucket_policy",
            "get_bucket_ownership_controls",
            "get_bucket_lifecycle_configuration",
            "list_object_versions",
            "list_multipart_uploads",
            "head_object",
        }
    ),
    "dynamodb": frozenset(
        {"describe_table", "list_tables", "describe_continuous_backups", "list_tags_of_resource"}
    ),
    "secretsmanager": frozenset({"describe_secret", "list_secrets"}),
    "eks": frozenset(
        {"describe_cluster", "list_clusters", "list_nodegroups", "describe_nodegroup"}
    ),
    "elbv2": frozenset({"describe_load_balancers", "describe_target_groups", "describe_tags"}),
    "resourcegroupstaggingapi": frozenset({"get_resources"}),
    "lambda": frozenset({"list_functions", "list_tags"}),
    "glue": frozenset({"get_jobs", "get_tags"}),
    "stepfunctions": frozenset({"list_state_machines", "list_tags_for_resource"}),
    "events": frozenset({"list_rules", "list_tags_for_resource"}),
}


_DISCOVERY_COVERAGE = {
    "EC2_NETWORK": ("ec2", "describe_vpcs"),
    "EC2_SUBNETS": ("ec2", "describe_subnets"),
    "EC2_ROUTES": ("ec2", "describe_route_tables"),
    "EC2_SECURITY_GROUPS": ("ec2", "describe_security_groups"),
    "EC2_ENDPOINTS": ("ec2", "describe_vpc_endpoints"),
    "EBS": ("ec2", "describe_volumes"),
    "ENI": ("ec2", "describe_network_interfaces"),
    "EIP": ("ec2", "describe_addresses"),
    "EKS": ("eks", "list_clusters"),
    "ELB": ("elbv2", "describe_load_balancers"),
    "TARGET_GROUPS": ("elbv2", "describe_target_groups"),
    "OPENSEARCH": ("opensearch", "list_domain_names"),
    "S3": ("s3", "list_buckets"),
    "DYNAMODB": ("dynamodb", "list_tables"),
    "ECR": ("ecr", "describe_repositories"),
    "CLOUDWATCH_LOGS": ("logs", "describe_log_groups"),
    "CLOUDWATCH_ALARMS": ("cloudwatch", "describe_alarms"),
    "SECRETS_MANAGER": ("secretsmanager", "list_secrets"),
    "KMS": ("kms", "list_keys"),
    "IAM_ROLES": ("iam", "list_roles"),
    "IAM_POLICIES": ("iam", "list_policies"),
    "LAMBDA": ("lambda", "list_functions"),
    "GLUE": ("glue", "get_jobs"),
    "STEP_FUNCTIONS": ("stepfunctions", "list_state_machines"),
    "EVENTBRIDGE": ("events", "list_rules"),
    "TAG_API": ("resourcegroupstaggingapi", "get_resources"),
}


RESOLUTION_METHODS = {
    "sts": frozenset({"get_caller_identity"}),
    "s3": frozenset({"head_object", "get_object", "list_buckets", "get_bucket_tagging"}),
    "ec2": frozenset(
        {
            "describe_vpc_endpoints",
            "describe_vpcs",
            "describe_subnets",
            "describe_route_tables",
            "describe_security_groups",
            "describe_network_interfaces",
        }
    ),
    "iam": frozenset(
        {
            "list_roles",
            "get_role",
            "list_policies",
            "list_policy_tags",
            "list_entities_for_policy",
        }
    ),
    "kms": frozenset({"list_keys", "describe_key", "list_aliases", "list_resource_tags"}),
    "cloudtrail": frozenset({"lookup_events"}),
    "ce": frozenset({"get_cost_and_usage"}),
}

FOLLOWUP_METHODS = {
    "sts": frozenset({"get_caller_identity"}),
    "s3": frozenset({"head_object", "get_object"}),
    "ec2": RESOLUTION_METHODS["ec2"],
    "iam": frozenset({"get_role", "list_entities_for_policy"}),
    "cloudtrail": frozenset({"lookup_events"}),
    "ce": frozenset({"get_cost_and_usage"}),
}
PREREQUISITE_METHODS = {
    "sts": frozenset({"get_caller_identity"}),
    "s3": frozenset(
        {
            "head_object",
            "get_object",
            "list_object_versions",
            "list_multipart_uploads",
            "list_parts",
        }
    ),
    "ec2": frozenset({"describe_route_tables"}),
    "iam": frozenset(
        {
            "get_role",
            "list_entities_for_policy",
            "get_user",
            "get_context_keys_for_principal_policy",
            "simulate_principal_policy",
        }
    ),
    "kms": frozenset({"describe_key", "get_key_policy"}),
    "ce": frozenset({"get_cost_and_usage"}),
    "ecr": frozenset({"describe_images"}),
    "dynamodb": frozenset({"describe_table"}),
}
PREREQUISITE_CORRECTION_METHODS = {
    "sts": frozenset({"get_caller_identity"}),
    "s3": frozenset({"head_object", "get_object"}),
    "iam": frozenset(
        {
            "get_user",
            "get_context_keys_for_principal_policy",
            "simulate_principal_policy",
            "list_entities_for_policy",
        }
    ),
    "kms": frozenset({"describe_key", "get_key_policy"}),
}
FOLLOWUP_NETWORK = {
    "EC2_NETWORK": ("describe_vpcs", "VpcIds", "Vpcs", "VpcId", 2),
    "EC2_SECURITY_GROUPS": ("describe_security_groups", "GroupIds", "SecurityGroups", "GroupId", 3),
    "EC2_SUBNETS": ("describe_subnets", "SubnetIds", "Subnets", "SubnetId", 5),
    "EC2_ROUTES": ("describe_route_tables", "RouteTableIds", "RouteTables", "RouteTableId", 3),
    "ENI": (
        "describe_network_interfaces",
        "NetworkInterfaceIds",
        "NetworkInterfaces",
        "NetworkInterfaceId",
        16,
    ),
}


_DIAGNOSTIC_METHODS = {
    **_READ_METHODS,
    "s3": (_READ_METHODS["s3"] - {"list_object_versions", "list_multipart_uploads"})
    | {"get_object"},
    "ecr": _READ_METHODS["ecr"] - {"describe_images"},
    "iam": _READ_METHODS["iam"]
    | {
        "get_user",
        "list_attached_user_policies",
        "list_user_policies",
        "get_user_policy",
        "list_groups_for_user",
        "list_attached_group_policies",
        "list_group_policies",
        "get_group_policy",
        "simulate_principal_policy",
    },
    "ce": frozenset({"get_cost_and_usage", "list_cost_allocation_tags"}),
    "cloudtrail": frozenset({"lookup_events"}),
    "sts": frozenset({"get_caller_identity"}),
}
# Exact SDK control-plane endpoints for this approved account/Region inventory.
# In particular SDK service names are not endpoint prefixes (ECR, CloudWatch).
# New services require an explicit entry and real SDK request-preparation coverage.
_DIAGNOSTIC_ENDPOINTS: Mapping[str, tuple[str, str]] = {
    "ec2": ("ap-southeast-1", "ec2.ap-southeast-1.amazonaws.com"),
    "logs": ("ap-southeast-1", "logs.ap-southeast-1.amazonaws.com"),
    "cloudwatch": ("ap-southeast-1", "monitoring.ap-southeast-1.amazonaws.com"),
    "opensearch": ("ap-southeast-1", "es.ap-southeast-1.amazonaws.com"),
    "kms": ("ap-southeast-1", "kms.ap-southeast-1.amazonaws.com"),
    "iam": ("us-east-1", "iam.amazonaws.com"),
    "ecr": ("ap-southeast-1", "api.ecr.ap-southeast-1.amazonaws.com"),
    "s3": ("ap-southeast-1", "s3.ap-southeast-1.amazonaws.com"),
    "dynamodb": ("ap-southeast-1", "dynamodb.ap-southeast-1.amazonaws.com"),
    "secretsmanager": ("ap-southeast-1", "secretsmanager.ap-southeast-1.amazonaws.com"),
    "eks": ("ap-southeast-1", "eks.ap-southeast-1.amazonaws.com"),
    "elbv2": ("ap-southeast-1", "elasticloadbalancing.ap-southeast-1.amazonaws.com"),
    "resourcegroupstaggingapi": ("ap-southeast-1", "tagging.ap-southeast-1.amazonaws.com"),
    "lambda": ("ap-southeast-1", "lambda.ap-southeast-1.amazonaws.com"),
    "glue": ("ap-southeast-1", "glue.ap-southeast-1.amazonaws.com"),
    "stepfunctions": ("ap-southeast-1", "states.ap-southeast-1.amazonaws.com"),
    "events": ("ap-southeast-1", "events.ap-southeast-1.amazonaws.com"),
    "ce": ("us-east-1", "ce.us-east-1.amazonaws.com"),
    "cloudtrail": ("ap-southeast-1", "cloudtrail.ap-southeast-1.amazonaws.com"),
    "sts": ("ap-southeast-1", "sts.ap-southeast-1.amazonaws.com"),
}
_DIAGNOSTIC_STATE_BUCKET = "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1"
_DIAGNOSTIC_STATE_KEY = "sandbox/platform.tfstate"
_DIAGNOSTIC_EVENTS = frozenset(
    {
        "CreateLogGroup",
        "AssociateKmsKey",
        "PutResourcePolicy",
        "CreateDomain",
        "CreateServiceLinkedRole",
        "CreateGrant",
    }
)


class DiagnosticFatalError(ContractError):
    """Latched failure: no subsequent remote call is permitted in this collection."""


class DiagnosticCollectionError(ContractError):
    """A bounded query failed; independent approved reads may still be attempted."""


_DIAGNOSTIC_FATAL_REASONS = frozenset(
    {
        "RESOLUTION_ARGUMENTS_NOT_APPROVED",
        "RESOLUTION_ENDPOINT_TARGETS_NOT_BOUND",
        "RESOLUTION_BUCKET_REGION_REQUIRED",
        "RESOLUTION_RESOURCE_NOT_DISCOVERED",
        "RESOLUTION_BUCKET_NOT_DISCOVERED",
        "RESOLUTION_CLOUDTRAIL_INTERVAL",
        "RESOLUTION_BILLING_SCOPE",
        "RESOLUTION_ENDPOINT_STATE_BINDING",
        "RESOLUTION_ENDPOINT_RESPONSE_BINDING",
        "RESOLUTION_ROLE_IDENTITY",
        "RESOLUTION_EVENT_IDENTITY",
        "DIAGNOSTIC_REGION_OVERRIDE",
        "DIAGNOSTIC_TIME_LIMIT",
        "DIAGNOSTIC_REQUEST_LIMIT",
        "DIAGNOSTIC_API_NOT_APPROVED",
        "DIAGNOSTIC_ARGUMENT_IDENTITY_OR_SCOPE_REJECTED",
        "DIAGNOSTIC_ENDPOINT_NOT_APPROVED",
        "DIAGNOSTIC_RETRY_CONFIGURATION",
        "DIAGNOSTIC_REDIRECT_GUARD_UNAVAILABLE",
        "DIAGNOSTIC_REDIRECT_NOT_APPROVED",
        "DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED",
        "DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED",
        "DIAGNOSTIC_AWS_IDENTITY_MISMATCH",
        "DIAGNOSTIC_COLLECTION_ITEM_LIMIT",
        "DIAGNOSTIC_BUCKET_OWNER_REQUIRED",
        "DIAGNOSTIC_STATE_TARGET_NOT_APPROVED",
        "DIAGNOSTIC_IAM_POLICY_SCOPE",
        "DIAGNOSTIC_CALLER_SCOPE",
        "DIAGNOSTIC_CALLER_GROUP_SCOPE",
        "DIAGNOSTIC_UNATTACHED_AWS_POLICY",
        "DIAGNOSTIC_SIMULATION_SCOPE",
        "DIAGNOSTIC_SIMULATION_ACTIONS",
        "DIAGNOSTIC_SIMULATION_TARGETS",
        "DIAGNOSTIC_SIMULATION_CONTEXT",
        "DIAGNOSTIC_CLOUDTRAIL_SCOPE",
        "DIAGNOSTIC_COST_TAG_SCOPE",
        "DIAGNOSTIC_BILLING_SCOPE",
        "DIAGNOSTIC_STATE_DRIFT",
        "DIAGNOSTIC_STATE_IDENTITY_CHANGED",
        "DIAGNOSTIC_SERVICE_ROLE_IDENTITY",
        "DIAGNOSTIC_CALLER_POLICY_IDENTITY",
        "DIAGNOSTIC_EVENT_REGION",
        "DIAGNOSTIC_EVENT_IDENTITY",
        "DIAGNOSTIC_EVENT_INTERVAL",
        "DIAGNOSTIC_NATIVE_IDENTITY_OR_ROUTING",
        "DIAGNOSTIC_FINAL_REPOSITORY_DRIFT",
        "DIAGNOSTIC_FINAL_INPUT_DRIFT",
        "DIAGNOSTIC_FINAL_STATE_DRIFT",
        "DIAGNOSTIC_AMBIENT_CONFIGURATION_REJECTED",
    }
)


def diagnostic_failure_reason(exc: Exception) -> str:
    """Only reviewed codes escape; never exception messages or AWS response values."""
    if isinstance(exc, DiagnosticFatalError):
        return str(exc) if str(exc) in _DIAGNOSTIC_FATAL_REASONS else "DIAGNOSTIC_SAFETY_STOP"
    if isinstance(exc, DiagnosticCollectionError):
        return (
            str(exc)
            if str(exc)
            in {
                "DIAGNOSTIC_RESPONSE_SIZE_LIMIT",
                "DIAGNOSTIC_QUERY_ITEM_LIMIT",
                "RESOLUTION_ENUMERATION_PAGE_LIMIT",
                "RESOLUTION_PRESERVATION_CAPACITY_RESERVED",
                "RESOLUTION_DISCOVERY_SHAPE",
                "RESOLUTION_DISCOVERY_IDENTITY",
                "RESOLUTION_TAG_PAGINATION_INCOMPLETE",
            }
            else "DIAGNOSTIC_QUERY_UNRESOLVED"
        )
    response = getattr(exc, "response", None)
    error = response.get("Error") if isinstance(response, dict) else None
    code = error.get("Code") if isinstance(error, dict) else None
    return {
        "AccessDenied": "NATIVE_ACCESS_DENIED",
        "AccessDeniedException": "NATIVE_ACCESS_DENIED",
        "UnauthorizedOperation": "NATIVE_ACCESS_DENIED",
        "ThrottlingException": "NATIVE_THROTTLED",
        "SDK_PARAMETER_VALIDATION_FAILED": "NATIVE_SDK_PARAMETER_VALIDATION_FAILED",
        "SDK_TRANSPORT_FAILED": "NATIVE_TRANSPORT_FAILED",
        "SDK_CREDENTIALS_UNAVAILABLE": "NATIVE_CREDENTIALS_UNAVAILABLE",
    }.get(code if isinstance(code, str) else "", "NATIVE_READ_UNAVAILABLE")


class DiagnosticReadError(ContractError):
    def __init__(self, code: str) -> None:
        super().__init__("DIAGNOSTIC_READ_UNAVAILABLE")
        self.response = {"Error": {"Code": code}}


class _DiagnosticClient:
    def __init__(self, session: DiagnosticAwsSession, service: str) -> None:
        self.session, self.service = session, service

    def __getattr__(self, method: str) -> Callable[..., dict[str, object]]:
        def invoke(**arguments: object) -> dict[str, object]:
            return self.session.call(self.service, method, arguments)

        return invoke


class DiagnosticAwsSession:
    """Read-only, budgeted proxy reused by native readers and independent discovery."""

    def __init__(
        self,
        provider: Boto3AwsInventoryProvider,
        *,
        monotonic: Callable[[], float] = time.monotonic,
        resolution_only: bool = False,
        resolution_followup: bool = False,
        prerequisite: bool = False,
        prerequisite_correction: bool = False,
    ) -> None:
        if (
            (prerequisite_correction and not prerequisite)
            or (resolution_followup and not resolution_only)
            or (prerequisite and (not resolution_only or resolution_followup))
        ):
            raise ContractError("RESOLUTION_EXACT_SCOPE_REQUIRED")
        self._source = provider
        self.resolution_only = resolution_only
        self.resolution_followup = resolution_followup
        self.prerequisite = prerequisite
        self.prerequisite_correction = prerequisite_correction
        self.prerequisite_targets: dict[str, str] = {}
        self.prerequisite_context: list[dict[str, object]] = []
        self.prerequisite_uploads: set[tuple[str, str, str]] = set()
        self.prerequisite_pages: dict[str, set[bytes]] = {}
        self.prerequisite_used_pages: set[tuple[str, bytes]] = set()
        self.prerequisite_state_conditions: dict[str, object] = {}
        self.followup_rows: dict[str, list[dict[str, object]]] = {}
        self.followup_targets: dict[str, list[str]] = {}
        self.followup_endpoint_rows: dict[str, dict[str, object]] = {}
        self.followup_vpc: str | None = None
        self.followup_tokens: dict[str, set[str]] = {}
        self.followup_used_tokens: set[tuple[str, str]] = set()
        self.limits = RESOLUTION_LIMITS if resolution_only else DIAGNOSTIC_LIMITS
        if prerequisite:
            self.limits = PREREQUISITE_LIMITS
        if prerequisite_correction:
            self.limits = PREREQUISITE_CORRECTION_LIMITS
        self.resolution_endpoints: frozenset[str] = frozenset()
        self.resolution_candidates: dict[str, set[str]] = {
            "RoleName": {"AWSServiceRoleForAmazonOpenSearchService"},
            "PolicyArn": set(),
            "KeyId": set(),
            "Bucket": set(),
        }
        self.preservation_phase = False
        self.enumeration_pages: dict[str, int] = {}
        self.partial_items: list[dict[str, object]] = []
        self._monotonic = monotonic
        self._started = monotonic()
        self._last_identity: float | None = None
        self.requests = 0
        self.request_counts: dict[str, int] = {}
        self.billing_requests = 0
        self.simulation_requests = 0
        self.discovery_items = 0
        self.fatal_reason: str | None = None
        self._event_next_at = 0.0
        self._attached_policies: set[str] = set()
        self._caller_groups: set[str] = set()
        self._simulation_targets: dict[str, tuple[str, ...]] = {}
        self._billing_end: str | None = None
        self._verified_regional_buckets: set[str] = set()
        self.provider = Boto3AwsInventoryProvider(
            client_factory=self.client,
            native_lister=None,
            region=APPROVED_AWS_REGION,
            account_id=APPROVED_AWS_ACCOUNT_ID,
            caller_arn=APPROVED_CALLER_ARN,
        )

    def client(self, service: str, region: str) -> object:
        if region != APPROVED_AWS_REGION:
            self.reject("DIAGNOSTIC_REGION_OVERRIDE")
        return _DiagnosticClient(self, service)

    def reject(self, reason: str) -> NoReturn:
        self.fatal_reason = reason
        raise DiagnosticFatalError(reason)

    def checkpoint(self) -> None:
        if self.fatal_reason is not None:
            raise DiagnosticFatalError(self.fatal_reason)
        if self._monotonic() - self._started >= self.limits.elapsed_seconds:
            self.reject("DIAGNOSTIC_TIME_LIMIT")
        if self.requests >= self.limits.requests:
            self.reject("DIAGNOSTIC_REQUEST_LIMIT")

    def verify_identity(self) -> None:
        self.call("sts", "get_caller_identity", {})

    def call(self, service: str, method: str, arguments: dict[str, object]) -> dict[str, object]:
        self.checkpoint()
        methods = (
            PREREQUISITE_CORRECTION_METHODS
            if self.prerequisite_correction
            else PREREQUISITE_METHODS
            if self.prerequisite
            else FOLLOWUP_METHODS
            if self.resolution_followup
            else (RESOLUTION_METHODS if self.resolution_only else _DIAGNOSTIC_METHODS)
        )
        if method not in methods.get(service, frozenset()):
            self.reject("DIAGNOSTIC_API_NOT_APPROVED")
        if self.resolution_only and self._monotonic() - self._started >= 855:
            self.reject("DIAGNOSTIC_TIME_LIMIT")
        if (
            self.resolution_only
            and not self.preservation_phase
            and (
                self.requests >= self.limits.requests - 8
                or self._monotonic() - self._started >= self.limits.elapsed_seconds - 120
            )
        ):
            raise DiagnosticCollectionError("RESOLUTION_PRESERVATION_CAPACITY_RESERVED")
        try:
            reject_ambient_aws_overrides()
        except ContractError:
            self.reject("DIAGNOSTIC_AMBIENT_CONFIGURATION_REJECTED")
        if service != "sts" and (
            self._last_identity is None or self._monotonic() - self._last_identity >= 60
        ):
            self.verify_identity()
        if self.prerequisite_correction:
            # An identity refresh is itself a request and can reach a budget boundary.
            self.checkpoint()
            if not self.preservation_phase and (
                self.requests >= self.limits.requests - 8
                or self._monotonic() - self._started >= self.limits.elapsed_seconds - 120
            ):
                raise DiagnosticCollectionError("RESOLUTION_PRESERVATION_CAPACITY_RESERVED")
        try:
            self._arguments(service, method, arguments)
        except DiagnosticFatalError:
            raise
        except ContractError:
            self.reject("DIAGNOSTIC_ARGUMENT_IDENTITY_OR_SCOPE_REJECTED")
        route = _DIAGNOSTIC_ENDPOINTS.get(service)
        if route is None:
            self.reject("DIAGNOSTIC_ENDPOINT_NOT_APPROVED")
        region, host = route
        client = self._source._client_factory(service, region)
        metadata = getattr(client, "meta", None)
        endpoint = getattr(metadata, "endpoint_url", "")
        if not _diagnostic_url_allowed(endpoint, {host}, endpoint=True):
            self.reject("DIAGNOSTIC_ENDPOINT_NOT_APPROVED")
        retries = getattr(getattr(metadata, "config", None), "retries", {})
        if not isinstance(retries, dict) or retries.get("total_max_attempts") != 1:
            self.reject("DIAGNOSTIC_RETRY_CONFIGURATION")
        events = getattr(metadata, "events", None)
        register = getattr(events, "register", None)
        if not callable(register):
            self.reject("DIAGNOSTIC_REDIRECT_GUARD_UNAVAILABLE")

        def guard_send(request: object, **_kwargs: object) -> None:
            request_url = getattr(request, "url", "")
            hosts = {host}
            bucket = arguments.get("Bucket")
            if service == "s3" and isinstance(bucket, str):
                hosts.add(bucket + ".s3." + APPROVED_AWS_REGION + ".amazonaws.com")
            if not _diagnostic_url_allowed(request_url, hosts):
                self.reject("DIAGNOSTIC_INITIAL_HOST_NOT_APPROVED")

        register("before-send.*.*", guard_send, unique_id="w5-004-diagnostic-routing")

        def guard_redirect(response: object = None, **_kwargs: object) -> None:
            # Run before SDK redirect handlers can issue a region-discovery or retry request.
            if isinstance(response, tuple) and response:
                status = getattr(response[0], "status_code", None)
                if type(status) is int and 300 <= status < 400:
                    self.reject("DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED")

        register_first = getattr(events, "register_first", None)
        if not callable(register_first):
            self.reject("DIAGNOSTIC_REDIRECT_GUARD_UNAVAILABLE")
        register_first("needs-retry.*.*", guard_redirect, unique_id="w5-004-no-http-redirect")
        if service == "ce":
            if self.billing_requests >= self.limits.billing_requests:
                raise ContractError("DIAGNOSTIC_BILLING_LIMIT")
            self.billing_requests += 1
        if method == "simulate_principal_policy":
            if self.simulation_requests >= self.limits.simulation_requests:
                raise ContractError("DIAGNOSTIC_SIMULATION_LIMIT")
            self.simulation_requests += 1
        if service == "cloudtrail":
            # Rate pacing is not an operation retry or an eventual-consistency workaround.
            delay = self._event_next_at - self._monotonic()
            if delay > 0:
                time.sleep(min(delay, 0.5))
            self._event_next_at = self._monotonic() + 0.5
        self.checkpoint()
        if self.resolution_only and (
            bool(self._prerequisite_markers(method))
            if self.prerequisite
            else method.startswith("list_") or service in {"ec2", "cloudtrail", "ce"}
        ):
            page_keys = {
                "NextToken",
                "Marker",
                "ContinuationToken",
                "NextPageToken",
                "MaxResults",
                "MaxItems",
                "Limit",
                "MaxBuckets",
                "KeyMarker",
                "VersionIdMarker",
                "UploadIdMarker",
                "PartNumberMarker",
                "nextToken",
                "MaxKeys",
                "MaxUploads",
                "MaxParts",
                "maxResults",
            }
            page_identity = (
                service
                + "/"
                + method
                + canonical_json_bytes(
                    {
                        key: value.isoformat() if isinstance(value, datetime) else value
                        for key, value in arguments.items()
                        if key not in page_keys
                    }
                ).decode()
            )
            count = self.enumeration_pages.get(page_identity, 0)
            if count >= self.limits.pages:
                raise DiagnosticCollectionError("RESOLUTION_ENUMERATION_PAGE_LIMIT")
            self.enumeration_pages[page_identity] = count + 1
        self.requests += 1
        request_key = service + "/" + method
        self.request_counts[request_key] = self.request_counts.get(request_key, 0) + 1
        try:
            response = getattr(client, method)(**arguments)
        except DiagnosticFatalError:
            raise
        except Exception as exc:
            value = getattr(exc, "response", {})
            response_metadata = value.get("ResponseMetadata", {}) if isinstance(value, dict) else {}
            status = (
                response_metadata.get("HTTPStatusCode")
                if isinstance(response_metadata, dict)
                else None
            )
            if type(status) is int and 300 <= status < 400:
                self.reject("DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED")
            error = value.get("Error", {}) if isinstance(value, dict) else {}
            code = error.get("Code", "") if isinstance(error, dict) else ""
            safe = (
                code
                if isinstance(code, str)
                and code
                in {
                    "NoSuchEntity",
                    "NoSuchBucket",
                    "NoSuchKey",
                    "NotFound",
                    "404",
                    "ResourceNotFoundException",
                    "NotFoundException",
                    "RepositoryNotFoundException",
                    "AccessDenied",
                    "AccessDeniedException",
                    "UnauthorizedOperation",
                    "ThrottlingException",
                    "NoSuchTagSet",
                    "SDK_PARAMETER_VALIDATION_FAILED",
                    "SDK_TRANSPORT_FAILED",
                    "SDK_CREDENTIALS_UNAVAILABLE",
                }
                else {
                    "ParamValidationError": "SDK_PARAMETER_VALIDATION_FAILED",
                    "EndpointConnectionError": "SDK_TRANSPORT_FAILED",
                    "ConnectTimeoutError": "SDK_TRANSPORT_FAILED",
                    "ReadTimeoutError": "SDK_TRANSPORT_FAILED",
                    "ConnectionClosedError": "SDK_TRANSPORT_FAILED",
                    "NoCredentialsError": "SDK_CREDENTIALS_UNAVAILABLE",
                    "PartialCredentialsError": "SDK_CREDENTIALS_UNAVAILABLE",
                }.get(type(exc).__name__, "UNCLASSIFIED_SERVICE_FAILURE")
            )
            raise DiagnosticReadError(safe) from None
        if not isinstance(response, dict):
            raise ContractError("DIAGNOSTIC_RESPONSE_SHAPE")
        if self.prerequisite:
            self._remember_prerequisite_page(service, method, arguments, response)
            if method == "head_object":
                self.prerequisite_state_conditions = {
                    key: response[source]
                    for source, key in (("VersionId", "VersionId"), ("ETag", "IfMatch"))
                    if source in response
                }
        if self.resolution_followup:
            identity = self._followup_page_identity(service, method, arguments)
            for key in ("NextToken", "Marker", "NextPageToken"):
                token = response.get(key)
                if isinstance(token, str) and token:
                    self.followup_tokens.setdefault(identity, set()).add(token)
        response_metadata = response.get("ResponseMetadata", {})
        status = (
            response_metadata.get("HTTPStatusCode") if isinstance(response_metadata, dict) else None
        )
        if type(status) is int and 300 <= status < 400:
            self.reject("DIAGNOSTIC_HTTP_REDIRECT_NOT_APPROVED")
        if service == "s3" and method == "get_bucket_location":
            bucket = arguments.get("Bucket")
            if response.get("LocationConstraint") == APPROVED_AWS_REGION and isinstance(
                bucket, str
            ):
                self._verified_regional_buckets.add(bucket)
        if service == "sts":
            if response.get("Account") != APPROVED_AWS_ACCOUNT_ID or (
                response.get("Arn") != APPROVED_CALLER_ARN
            ):
                self.reject("DIAGNOSTIC_AWS_IDENTITY_MISMATCH")
            self._last_identity = self._monotonic()
        if method == "get_object":
            body = response.get("Body")
            if body is None or not callable(getattr(body, "read", None)):
                raise ContractError("DIAGNOSTIC_STATE_BODY")
            try:
                raw = body.read(DIAGNOSTIC_LIMITS.state_bytes + 1)
            finally:
                body.close()
            if not isinstance(raw, bytes) or len(raw) > DIAGNOSTIC_LIMITS.state_bytes:
                raise ContractError("DIAGNOSTIC_STATE_SIZE")
            return {
                "state_bytes": raw,
                "VersionId": response.get("VersionId"),
                "ETag": response.get("ETag"),
            }
        self._response_size(response)
        processed = sum(len(value) for value in response.values() if isinstance(value, list))
        self.discovery_items += processed
        if self.discovery_items > DIAGNOSTIC_LIMITS.discovery_items:
            self.reject("DIAGNOSTIC_COLLECTION_ITEM_LIMIT")
        if processed > DIAGNOSTIC_LIMITS.items_per_query:
            raise DiagnosticCollectionError("DIAGNOSTIC_QUERY_ITEM_LIMIT")
        if service == "iam":
            for field in ("AttachedPolicies", "Policies"):
                values = response.get(field, [])
                if isinstance(values, list):
                    for item in values:
                        if isinstance(item, dict) and isinstance(item.get("PolicyArn"), str):
                            self._attached_policies.add(item["PolicyArn"])
            user = response.get("User")
            boundary = user.get("PermissionsBoundary") if isinstance(user, dict) else None
            if isinstance(boundary, dict) and isinstance(
                boundary.get("PermissionsBoundaryArn"),
                str,
            ):
                self._attached_policies.add(boundary["PermissionsBoundaryArn"])
            groups = response.get("Groups", [])
            if isinstance(groups, list):
                for group in groups:
                    if isinstance(group, dict) and isinstance(group.get("GroupName"), str):
                        self._caller_groups.add(group["GroupName"])
            if len(self._caller_groups) > DIAGNOSTIC_LIMITS.caller_groups:
                raise ContractError("DIAGNOSTIC_CALLER_GROUP_LIMIT")
        if self.resolution_only and not self.prerequisite:
            self._remember_resolution_candidates(service, method, cast(dict[str, object], response))
        return cast(dict[str, object], response)

    def _response_size(self, response: object) -> None:
        def safe(value: object) -> object:
            if isinstance(value, datetime):
                return value.isoformat()
            if isinstance(value, dict):
                return {str(key): safe(child) for key, child in value.items()}
            if isinstance(value, list):
                return [safe(child) for child in value]
            return value

        # Byte accounting stays in memory; this payload is never a report.
        import json

        if (
            len(json.dumps(safe(response), allow_nan=False).encode())
            > DIAGNOSTIC_LIMITS.response_bytes
        ):
            raise DiagnosticCollectionError("DIAGNOSTIC_RESPONSE_SIZE_LIMIT")

    def bind_followup_evidence(self, raw: bytes, identity_raw: bytes) -> None:
        """Seed exact targets only from the approved immutable report, before any call."""
        if (
            not self.resolution_followup
            or self.requests
            or self.followup_rows
            or sha256_bytes(raw) != RESOLUTION_FOLLOWUP_EVIDENCE_SHA256
            or sha256_bytes(identity_raw) != RESOLUTION_FOLLOWUP_IDENTITY_SHA256
        ):
            raise ContractError("RESOLUTION_RETAINED_EVIDENCE_CHANGED")
        report = decode_json_strict(raw)
        identity = decode_json_strict(identity_raw)
        if (
            not isinstance(report, dict)
            or not isinstance(identity, dict)
            or identity.get("report_sha256") != sha256_bytes(raw)
            or report.get("operation_id") != "w5-004-resolution-evidence-001"
            or report.get("account_id") != APPROVED_AWS_ACCOUNT_ID
            or report.get("region") != APPROVED_AWS_REGION
        ):
            raise ContractError("RESOLUTION_RETAINED_EVIDENCE_BINDING_REQUIRED")
        checks = report.get("checks")
        if not isinstance(checks, list):
            raise ContractError("RESOLUTION_DISCOVERY_SHAPE")
        for check in checks:
            if not isinstance(check, dict) or not isinstance(check.get("check_id"), str):
                raise ContractError("RESOLUTION_DISCOVERY_SHAPE")
            name = cast(str, check["check_id"])
            if not name.startswith("discovery/"):
                continue
            details = dict(check["details"])
            category = name.removeprefix("discovery/")
            rows = decode_json_strict(details["resources"].encode())
            if (
                details.get("enumeration_complete") != "true"
                or category in self.followup_rows
                or not isinstance(rows, list)
                or any(
                    not isinstance(row, dict) or not isinstance(row.get("resource"), str)
                    for row in rows
                )
                or len({row["resource"] for row in rows}) != len(rows)
            ):
                raise ContractError("RESOLUTION_DISCOVERY_SHAPE")
            self.followup_rows[category] = rows
        if set(self.followup_rows) != {*FOLLOWUP_NETWORK, "IAM_ROLES", "IAM_POLICIES", "KMS", "S3"}:
            raise ContractError("RESOLUTION_DISCOVERY_SHAPE")
        for category, (method, _field, _rows, _key, count) in FOLLOWUP_NETWORK.items():
            ids = sorted(cast(str, row["resource"]) for row in self.followup_rows[category])
            if len(ids) != count or any(
                re.fullmatch(r"(?:vpc|sg|subnet|rtb|eni)-[0-9a-f]+", item) is None for item in ids
            ):
                raise ContractError("RESOLUTION_DISCOVERY_IDENTITY")
            self.followup_targets[method] = ids
        roles = self.followup_rows["IAM_ROLES"]
        policies = self.followup_rows["IAM_POLICIES"]
        if len(roles) != 32 or len(policies) != 1:
            raise ContractError("RESOLUTION_DISCOVERY_IDENTITY")
        self.resolution_candidates["RoleName"].update(cast(str, row["resource"]) for row in roles)
        policy = cast(str, policies[0]["resource"])
        if policy != (
            "arn:aws:iam::526338061652:policy/service-role/"
            "AWSLambdaBasicExecutionRole-b48d6859-d98d-40eb-b786-c933f136e828"
        ):
            raise ContractError("RESOLUTION_DISCOVERY_IDENTITY")
        self.resolution_candidates["PolicyArn"].add(policy)

    @staticmethod
    def _followup_page_identity(service: str, method: str, arguments: dict[str, object]) -> str:
        return (
            service
            + "/"
            + method
            + canonical_json_bytes(
                {
                    key: value.isoformat() if isinstance(value, datetime) else value
                    for key, value in arguments.items()
                    if key not in {"NextToken", "Marker", "NextPageToken"}
                }
            ).decode()
        )

    def _followup_arguments(self, service: str, method: str, arguments: dict[str, object]) -> None:
        if not self.followup_rows:
            self.reject("RESOLUTION_RETAINED_EVIDENCE_BINDING_REQUIRED")
        permitted: set[str]
        if service == "sts":
            permitted = set()
        elif service == "s3":
            permitted = {"Bucket", "Key", "ExpectedBucketOwner", "IfMatch", "VersionId"}
        elif method == "describe_vpc_endpoints":
            permitted = {"VpcEndpointIds", "NextToken"}
            if len(self.resolution_endpoints) != 8 or arguments.get("VpcEndpointIds") != sorted(
                self.resolution_endpoints
            ):
                self.reject("RESOLUTION_ENDPOINT_TARGETS_NOT_BOUND")
        elif service == "ec2":
            spec = next((value for value in FOLLOWUP_NETWORK.values() if value[0] == method), None)
            if spec is None:
                self.reject("DIAGNOSTIC_API_NOT_APPROVED")
            permitted = {spec[1], "NextToken"}
            if (
                not self.followup_targets.get(method)
                or arguments.get(spec[1]) != self.followup_targets[method]
            ):
                self.reject("RESOLUTION_RESOURCE_NOT_DISCOVERED")
        elif method == "get_role":
            permitted = {"RoleName"}
            if arguments.get("RoleName") not in self.resolution_candidates["RoleName"]:
                self.reject("RESOLUTION_RESOURCE_NOT_DISCOVERED")
        elif method == "list_entities_for_policy":
            permitted = {"PolicyArn", "PolicyUsageFilter", "MaxItems", "Marker"}
            if (
                arguments.get("PolicyArn") not in self.resolution_candidates["PolicyArn"]
                or arguments.get("PolicyUsageFilter")
                not in {"PermissionsPolicy", "PermissionsBoundary"}
                or type(arguments.get("MaxItems")) is not int
                or arguments["MaxItems"] != 100
            ):
                self.reject("RESOLUTION_RESOURCE_NOT_DISCOVERED")
        elif service == "cloudtrail":
            permitted = {"LookupAttributes", "StartTime", "EndTime", "MaxResults", "NextToken"}
            if type(arguments.get("MaxResults")) is not int or arguments["MaxResults"] != 50:
                self.reject("RESOLUTION_ARGUMENTS_NOT_APPROVED")
        elif service == "ce":
            permitted = {
                "TimePeriod",
                "Granularity",
                "Metrics",
                "Filter",
                "GroupBy",
                "NextPageToken",
            }
            if arguments.get("GroupBy") != [
                {"Type": "DIMENSION", "Key": "SERVICE"},
                {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
            ]:
                self.reject("RESOLUTION_BILLING_SCOPE")
        else:
            self.reject("DIAGNOSTIC_API_NOT_APPROVED")
        if set(arguments) - permitted:
            self.reject("RESOLUTION_ARGUMENTS_NOT_APPROVED")
        identity = self._followup_page_identity(service, method, arguments)
        for key in ("NextToken", "Marker", "NextPageToken"):
            if key not in arguments:
                continue
            token = arguments[key]
            if (
                not isinstance(token, str)
                or not token
                or token not in self.followup_tokens.get(identity, set())
                or (identity, token) in self.followup_used_tokens
            ):
                self.reject("RESOLUTION_ARGUMENTS_NOT_APPROVED")
            self.followup_used_tokens.add((identity, token))

    @staticmethod
    def followup_denial_details(event: dict[str, object]) -> dict[str, object]:
        """Never disclose the message; an action is evidence only when explicitly denied."""
        message = event.get("errorMessage")
        text = message.casefold() if isinstance(message, str) else ""
        actions = (
            "logs:createloggroup",
            "logs:tagresource",
            "logs:associatekmskey",
            "logs:putretentionpolicy",
            "kms:encrypt",
            "kms:decrypt",
            "kms:generatedatakey",
            "kms:describekey",
            "kms:creategrant",
        )
        named = [
            action
            for action in actions
            if re.search(
                r"(?:not authorized to perform|denied(?: to perform)?|cannot perform)\s*:?\s*"
                + re.escape(action)
                + r"(?![a-z])",
                text,
            )
        ]
        decision = "UNSPECIFIED"
        if named and "explicit deny" in text:
            decision = "EXPLICIT_DENY_REPORTED"
        elif named and (
            "no identity-based policy allows" in text or "no resource-based policy allows" in text
        ):
            decision = "MISSING_ALLOW_REPORTED"
        identity = event.get("eventID")
        valid_id = isinstance(identity, str) and re.fullmatch(r"[0-9a-fA-F-]{36}", identity)
        return {
            "event_identity": identity if valid_id else None,
            "message_available": isinstance(message, str) and bool(message),
            "explicit_denied_actions": named,
            "denial_mechanism": decision,
            "authorization_cause_established": len(named) == 1 and decision != "UNSPECIFIED",
            "permission_grant_recommended": False,
            "next_verification": "EXACT_NAMED_ACTION_AND_POLICY_LAYER_REVIEW"
            if named
            else "EXACT_FAILED_REQUEST_AUTHORIZATION_CONTEXT_REQUIRED",
            "raw_error_message_retained": False,
        }

    def _resolution_arguments(
        self, service: str, method: str, arguments: dict[str, object]
    ) -> None:
        """Closed operation-specific arguments; identifiers derive only from bound discovery."""
        if self.resolution_followup:
            self._followup_arguments(service, method, arguments)
            if service not in {"ce", "cloudtrail"}:
                return
        pagination = {
            "NextToken",
            "Marker",
            "MaxResults",
            "MaxItems",
            "Limit",
            "ContinuationToken",
            "MaxBuckets",
            "NextPageToken",
        }
        fields: dict[str, set[str]] = {
            "get_caller_identity": set(),
            "head_object": {"Bucket", "Key", "ExpectedBucketOwner", "VersionId", "IfMatch"},
            "get_object": {"Bucket", "Key", "ExpectedBucketOwner", "VersionId", "IfMatch"},
            "list_buckets": {"BucketRegion", "ContinuationToken", "MaxBuckets"},
            "get_bucket_tagging": {"Bucket", "ExpectedBucketOwner"},
            "describe_vpc_endpoints": {"VpcEndpointIds", "NextToken", "MaxResults"},
            "get_role": {"RoleName"},
            "list_policies": {"Scope", "Marker", "MaxItems"},
            "list_policy_tags": {"PolicyArn", "Marker", "MaxItems"},
            "list_entities_for_policy": {"PolicyArn", "Marker", "MaxItems"},
            "describe_key": {"KeyId"},
            "list_resource_tags": {"KeyId", "Marker", "Limit"},
            "lookup_events": {
                "LookupAttributes",
                "StartTime",
                "EndTime",
                "MaxResults",
                "NextToken",
            },
            "get_cost_and_usage": {
                "TimePeriod",
                "Granularity",
                "Metrics",
                "Filter",
                "GroupBy",
                "NextPageToken",
            },
        }
        if set(arguments) - fields.get(method, pagination):
            self.reject("RESOLUTION_ARGUMENTS_NOT_APPROVED")
        if method == "describe_vpc_endpoints" and (
            not self.resolution_endpoints
            or len(self.resolution_endpoints) != 8
            or arguments.get("VpcEndpointIds") != sorted(self.resolution_endpoints)
        ):
            self.reject("RESOLUTION_ENDPOINT_TARGETS_NOT_BOUND")
        if method == "list_buckets" and arguments.get("BucketRegion") != APPROVED_AWS_REGION:
            self.reject("RESOLUTION_BUCKET_REGION_REQUIRED")
        for field in ("RoleName", "PolicyArn", "KeyId"):
            if field in arguments and arguments[field] not in self.resolution_candidates[field]:
                self.reject("RESOLUTION_RESOURCE_NOT_DISCOVERED")
        if (
            method == "get_bucket_tagging"
            and arguments.get("Bucket") not in (self.resolution_candidates["Bucket"])
        ):
            self.reject("RESOLUTION_BUCKET_NOT_DISCOVERED")
        if service == "cloudtrail" and (
            arguments.get("LookupAttributes")
            != [{"AttributeKey": "EventName", "AttributeValue": "CreateLogGroup"}]
            or arguments.get("StartTime") != parse_utc_timestamp(RESOLUTION_EVENTS_START, "start")
            or arguments.get("EndTime") != parse_utc_timestamp(RESOLUTION_EVENTS_END, "end")
        ):
            self.reject("RESOLUTION_CLOUDTRAIL_INTERVAL")
        if service == "ce" and (
            arguments.get("TimePeriod")
            != {"Start": RESOLUTION_BILLING_START, "End": RESOLUTION_BILLING_END}
            or arguments.get("Filter")
            != {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [APPROVED_AWS_ACCOUNT_ID]}}
            or arguments.get("Granularity") != "DAILY"
            or arguments.get("Metrics") != ["UnblendedCost"]
            or arguments.get("GroupBy", [])
            not in (
                [],
                [{"Type": "DIMENSION", "Key": "SERVICE"}],
                [
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                    {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
                ],
            )
        ):
            self.reject("RESOLUTION_BILLING_SCOPE")

    def _remember_resolution_candidates(
        self, service: str, method: str, response: dict[str, object]
    ) -> None:
        mapping = {
            "list_roles": ("Roles", "RoleName", "RoleName"),
            "list_policies": ("Policies", "Arn", "PolicyArn"),
            "list_keys": ("Keys", "KeyId", "KeyId"),
            "list_buckets": ("Buckets", "Name", "Bucket"),
        }
        if method not in mapping:
            return
        field, key, target = mapping[method]
        rows = response.get(field)
        if not isinstance(rows, list):
            raise DiagnosticCollectionError("RESOLUTION_DISCOVERY_SHAPE")
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get(key), str):
                raise DiagnosticCollectionError("RESOLUTION_DISCOVERY_IDENTITY")
            if service == "s3" and row.get("BucketRegion") != APPROVED_AWS_REGION:
                continue
            arn = row.get("Arn", row.get("KeyArn"))
            if isinstance(arn, str):
                pieces = arn.split(":", 5)
                if (
                    len(pieces) != 6
                    or pieces[0:2] != ["arn", "aws"]
                    or pieces[2] != service
                    or pieces[4] != APPROVED_AWS_ACCOUNT_ID
                    or pieces[3] != ("" if service == "iam" else APPROVED_AWS_REGION)
                ):
                    self.reject("DIAGNOSTIC_ARGUMENT_IDENTITY_OR_SCOPE_REJECTED")
            self.resolution_candidates[target].add(cast(str, row[key]))

    @staticmethod
    def _prerequisite_markers(method: str) -> dict[str, str]:
        return {
            "list_object_versions": {
                "NextKeyMarker": "KeyMarker",
                "NextVersionIdMarker": "VersionIdMarker",
            },
            "list_multipart_uploads": {
                "NextKeyMarker": "KeyMarker",
                "NextUploadIdMarker": "UploadIdMarker",
            },
            "list_parts": {"NextPartNumberMarker": "PartNumberMarker"},
            "list_entities_for_policy": {"Marker": "Marker"},
            "simulate_principal_policy": {"Marker": "Marker"},
            "get_cost_and_usage": {"NextPageToken": "NextPageToken"},
            "describe_images": {"nextToken": "nextToken"},
        }.get(method, {})

    def _prerequisite_page_key(
        self,
        service: str,
        method: str,
        arguments: dict[str, object],
    ) -> str:
        markers = self._prerequisite_markers(method).values()
        return (
            service
            + "/"
            + method
            + canonical_json_bytes(
                {key: value for key, value in arguments.items() if key not in markers}
            ).decode()
        )

    def _remember_prerequisite_page(
        self,
        service: str,
        method: str,
        arguments: dict[str, object],
        response: dict[str, object],
    ) -> None:
        markers = {
            dest: response[source]
            for source, dest in self._prerequisite_markers(method).items()
            if source in response
        }
        if markers:
            key = self._prerequisite_page_key(service, method, arguments)
            self.prerequisite_pages.setdefault(key, set()).add(canonical_json_bytes(markers))

    def prerequisite_enumerate(
        self,
        service: str,
        method: str,
        arguments: dict[str, object],
        result_key: str,
    ) -> tuple[list[dict[str, object]], bool]:
        """Bounded pages; only returned markers, no discovery fallback or raw persistence."""
        rows: list[dict[str, object]] = []
        query = dict(arguments)
        for _ in range(self.limits.pages):
            response = self.call(service, method, query)
            page = response.get(result_key, [])
            if not isinstance(page, list) or any(not isinstance(row, dict) for row in page):
                raise ContractError("PREREQUISITE_RESPONSE_STRUCTURE")
            rows.extend(cast(list[dict[str, object]], page))
            markers = {
                dest: response[source]
                for source, dest in self._prerequisite_markers(method).items()
                if response.get(source) is not None
            }
            if not markers:
                return rows, response.get("IsTruncated", False) is False
            if response.get("IsTruncated") is False:
                return rows, True
            query = {**arguments, **markers}
        return rows, False

    def prerequisite_policy_entities(self, usage: str) -> tuple[list[dict[str, str]], bool]:
        """Collect all three attachment arrays from the same bounded pages."""
        base: dict[str, object] = {
            "PolicyArn": PREREQUISITE_POLICY,
            "PolicyUsageFilter": usage,
            "MaxItems": 100,
        }
        query = dict(base)
        rows: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for _ in range(self.limits.pages):
            response = self.call("iam", "list_entities_for_policy", query)
            for plural, singular in (
                ("PolicyRoles", "Role"),
                ("PolicyUsers", "User"),
                ("PolicyGroups", "Group"),
            ):
                values = response.get(plural, [])
                if not isinstance(values, list):
                    raise ContractError("PREREQUISITE_RESPONSE_STRUCTURE")
                for value in values:
                    name = value.get(singular + "Name") if isinstance(value, dict) else None
                    if (
                        not isinstance(name, str)
                        or re.fullmatch(r"[\w+=,.@-]{1,128}", name) is None
                        or (singular, name) in seen
                    ):
                        raise ContractError("PREREQUISITE_RESPONSE_STRUCTURE")
                    seen.add((singular, name))
                    rows.append({"entity_type": singular, "name": name})
            if response.get("IsTruncated", False) is False:
                return rows, True
            token = response.get("Marker")
            if not isinstance(token, str) or not token:
                return rows, False
            query = {**base, "Marker": token}
        return rows, False

    def _prerequisite_arguments(
        self,
        service: str,
        method: str,
        arguments: dict[str, object],
    ) -> None:
        markers = set(self._prerequisite_markers(method).values())
        supplied = {key: value for key, value in arguments.items() if key in markers}
        if supplied:
            key = self._prerequisite_page_key(service, method, arguments)
            token = canonical_json_bytes(supplied)
            if (
                token not in self.prerequisite_pages.get(key, set())
                or (key, token) in self.prerequisite_used_pages
            ):
                self.reject("PREREQUISITE_PAGINATION_NOT_ISSUED")
            self.prerequisite_used_pages.add((key, token))
        actual = {key: value for key, value in arguments.items() if key not in markers}
        expected: dict[str, object]
        if service == "sts":
            expected = {}
        elif method in {"get_object", "head_object"}:
            expected = {
                "Bucket": "enterprise-ai-platform-sbx-tfstate-526338061652-ap-southeast-1",
                "Key": "sandbox/platform.tfstate",
                "ExpectedBucketOwner": APPROVED_AWS_ACCOUNT_ID,
            }
            for key in ("VersionId", "IfMatch"):
                if key in actual:
                    if (
                        not isinstance(actual[key], str)
                        or not actual[key]
                        or (actual[key] != self.prerequisite_state_conditions.get(key))
                    ):
                        self.reject("PREREQUISITE_STATE_CONDITION_INVALID")
                    expected[key] = actual[key]
            if method == "get_object" and actual.get("IfMatch") is None:
                self.reject("PREREQUISITE_STATE_CONDITION_INVALID")
        elif method == "describe_route_tables":
            expected = {"RouteTableIds": list(PREREQUISITE_ROUTES)}
        elif method == "get_role":
            role = actual.get("RoleName")
            if role not in PREREQUISITE_ROLES:
                self.reject("PREREQUISITE_RESOURCE_NOT_APPROVED")
            expected = {"RoleName": role}
        elif method == "list_entities_for_policy":
            usage = actual.get("PolicyUsageFilter")
            if usage not in {"PermissionsPolicy", "PermissionsBoundary"}:
                self.reject("PREREQUISITE_RESOURCE_NOT_APPROVED")
            expected = {
                "PolicyArn": PREREQUISITE_POLICY,
                "PolicyUsageFilter": usage,
                "MaxItems": 100,
            }
        elif method == "get_user":
            expected = {"UserName": "finopsinfra"}
        elif method == "get_context_keys_for_principal_policy":
            expected = {"PolicySourceArn": APPROVED_CALLER_ARN}
        elif method == "simulate_principal_policy":
            actions = actual.get("ActionNames")
            if (
                not isinstance(actions, list)
                or len(actions) != 1
                or (actions[0] not in PREREQUISITE_LOG_ACTIONS)
            ):
                self.reject("PREREQUISITE_ACTION_NOT_APPROVED")
            expected = {
                "PolicySourceArn": APPROVED_CALLER_ARN,
                "ActionNames": actions,
                "ResourceArns": [
                    "arn:aws:logs:ap-southeast-1:526338061652:log-group:"
                    + name
                    + ("" if actions[0] == "logs:TagResource" else ":*")
                    for name in PREREQUISITE_LOG_NAMES
                ],
                "MaxItems": 100,
            }
            if self.prerequisite_context:
                expected["ContextEntries"] = self.prerequisite_context
        elif service == "ce":
            expected = {
                "TimePeriod": {"Start": RESOLUTION_BILLING_START, "End": RESOLUTION_BILLING_END},
                "Granularity": "DAILY",
                "Metrics": ["UnblendedCost"],
                "Filter": {
                    "Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [APPROVED_AWS_ACCOUNT_ID]}
                },
                "GroupBy": [
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                    {"Type": "DIMENSION", "Key": "RECORD_TYPE"},
                ],
            }
        elif service == "kms":
            expected = {"KeyId": self.prerequisite_targets.get("kms")}
            if method == "get_key_policy":
                expected["PolicyName"] = "default"
        elif service == "dynamodb":
            expected = {"TableName": self.prerequisite_targets.get("dynamodb")}
        elif service == "ecr":
            expected = {
                "registryId": APPROVED_AWS_ACCOUNT_ID,
                "repositoryName": self.prerequisite_targets.get("ecr"),
                "maxResults": 1000,
            }
        elif service == "s3":
            bucket = actual.get("Bucket")
            if not isinstance(bucket, str) or bucket not in {
                self.prerequisite_targets.get("bootstrap_bucket"),
                self.prerequisite_targets.get("platform_bucket"),
            }:
                self.reject("PREREQUISITE_RESOURCE_NOT_APPROVED")
            expected = {"Bucket": bucket, "ExpectedBucketOwner": APPROVED_AWS_ACCOUNT_ID}
            if method == "list_parts":
                upload = (bucket, actual.get("Key"), actual.get("UploadId"))
                if upload not in self.prerequisite_uploads:
                    self.reject("PREREQUISITE_UPLOAD_NOT_BOUND")
                expected.update(Key=actual["Key"], UploadId=actual["UploadId"], MaxParts=1000)
            else:
                expected["MaxKeys" if method == "list_object_versions" else "MaxUploads"] = 1000
        else:
            self.reject("DIAGNOSTIC_API_NOT_APPROVED")
        if any(value is None for value in expected.values()) or (
            canonical_json_bytes(actual) != canonical_json_bytes(expected)
        ):
            self.reject("PREREQUISITE_EXACT_ARGUMENTS_REQUIRED")

    def _arguments(self, service: str, method: str, arguments: dict[str, object]) -> None:
        if self.prerequisite:
            self._prerequisite_arguments(service, method, arguments)
            return
        if self.resolution_only:
            self._resolution_arguments(service, method, arguments)
            if service in {"ce", "cloudtrail"}:
                return
        if service not in {"ce", "cloudtrail", "iam"}:
            _validate_native_scope(service, arguments)
        if service == "ecr" and arguments.get("registryId", APPROVED_AWS_ACCOUNT_ID) != (
            APPROVED_AWS_ACCOUNT_ID
        ):
            self.reject("DIAGNOSTIC_ARGUMENT_IDENTITY_OR_SCOPE_REJECTED")
        if (
            service == "s3"
            and "Bucket" in arguments
            and (arguments.get("ExpectedBucketOwner") != APPROVED_AWS_ACCOUNT_ID)
        ):
            self.reject("DIAGNOSTIC_BUCKET_OWNER_REQUIRED")
        if method in {"get_object", "head_object"} and (
            arguments.get("Bucket") != _DIAGNOSTIC_STATE_BUCKET
            or arguments.get("Key") != _DIAGNOSTIC_STATE_KEY
            or set(arguments) - {"Bucket", "Key", "ExpectedBucketOwner", "VersionId", "IfMatch"}
        ):
            self.reject("DIAGNOSTIC_STATE_TARGET_NOT_APPROVED")
        if service == "iam" and method == "list_policies" and arguments.get("Scope") != "Local":
            self.reject("DIAGNOSTIC_IAM_POLICY_SCOPE")
        if service == "iam" and "UserName" in arguments and arguments["UserName"] != "finopsinfra":
            self.reject("DIAGNOSTIC_CALLER_SCOPE")
        if (
            service == "iam"
            and "GroupName" in arguments
            and (arguments["GroupName"] not in self._caller_groups)
        ):
            self.reject("DIAGNOSTIC_CALLER_GROUP_SCOPE")
        if service == "iam" and isinstance(arguments.get("PolicyArn"), str):
            policy = cast(str, arguments["PolicyArn"])
            if policy.startswith("arn:aws:iam::aws:"):
                if policy not in self._attached_policies:
                    self.reject("DIAGNOSTIC_UNATTACHED_AWS_POLICY")
            else:
                _validate_native_scope(service, policy)
        if method == "simulate_principal_policy":
            actions = arguments.get("ActionNames")
            if arguments.get("PolicySourceArn") != APPROVED_CALLER_ARN or not isinstance(
                actions, list
            ):
                self.reject("DIAGNOSTIC_SIMULATION_SCOPE")
            if (
                not actions
                or not set(actions)
                <= {
                    "logs:CreateLogGroup",
                    "logs:TagResource",
                    "logs:AssociateKmsKey",
                    "logs:PutRetentionPolicy",
                    "logs:PutResourcePolicy",
                    "es:CreateDomain",
                    "iam:CreateServiceLinkedRole",
                }
                or set(arguments)
                - {
                    "PolicySourceArn",
                    "ActionNames",
                    "ResourceArns",
                    "ContextEntries",
                    "Marker",
                    "MaxItems",
                }
            ):
                self.reject("DIAGNOSTIC_SIMULATION_ACTIONS")
            expected_resources = self._simulation_targets.get(cast(list[str], actions)[0])
            if (
                len(actions) != 1
                or expected_resources is None
                or arguments.get("ResourceArns") != list(expected_resources)
            ):
                self.reject("DIAGNOSTIC_SIMULATION_TARGETS")
            expected_context: list[dict[str, object]] = []
            if actions == ["iam:CreateServiceLinkedRole"]:
                expected_context = [
                    {
                        "ContextKeyName": "iam:AWSServiceName",
                        "ContextKeyValues": ["opensearchservice.amazonaws.com"],
                        "ContextKeyType": "string",
                    }
                ]
            if arguments.get("ContextEntries", []) != expected_context:
                self.reject("DIAGNOSTIC_SIMULATION_CONTEXT")
        if service == "cloudtrail":
            attributes = arguments.get("LookupAttributes")
            if (
                not isinstance(attributes, list)
                or len(attributes) != 1
                or not isinstance(attributes[0], dict)
                or attributes[0].get("AttributeKey") != "EventName"
                or attributes[0].get("AttributeValue") not in _DIAGNOSTIC_EVENTS
                or arguments.get("StartTime") != datetime(2026, 9, 10, 7, 40, tzinfo=UTC)
                or arguments.get("EndTime") != datetime(2026, 9, 10, 8, 40, tzinfo=UTC)
                or set(arguments)
                - {
                    "LookupAttributes",
                    "StartTime",
                    "EndTime",
                    "MaxResults",
                    "NextToken",
                }
            ):
                self.reject("DIAGNOSTIC_CLOUDTRAIL_SCOPE")
        if service == "ce":
            if method == "list_cost_allocation_tags":
                if arguments.get("TagKeys") != ["Project"] or set(arguments) - {
                    "TagKeys",
                    "MaxResults",
                    "NextToken",
                }:
                    self.reject("DIAGNOSTIC_COST_TAG_SCOPE")
            else:
                account_filter = {
                    "Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [APPROVED_AWS_ACCOUNT_ID]}
                }
                tag_filter = {"Tags": {"Key": "Project", "Values": ["enterprise-ai-platform"]}}
                if (
                    arguments.get("Filter")
                    not in (
                        account_filter,
                        {"And": [account_filter, tag_filter]},
                    )
                    or arguments.get("Granularity") != "DAILY"
                    or arguments.get("Metrics") != ["UnblendedCost"]
                    or arguments.get("GroupBy") != [{"Type": "DIMENSION", "Key": "SERVICE"}]
                    or self._billing_end is None
                    or arguments.get("TimePeriod")
                    != {
                        "Start": "2026-09-08",
                        "End": self._billing_end,
                    }
                    or set(arguments)
                    - {
                        "Filter",
                        "Granularity",
                        "Metrics",
                        "GroupBy",
                        "TimePeriod",
                        "NextPageToken",
                    }
                ):
                    self.reject("DIAGNOSTIC_BILLING_SCOPE")

    def pages(
        self,
        service: str,
        method: str,
        arguments: dict[str, object],
        *,
        result_key: str,
        request_page_field: str = "NextToken",
        response_page_field: str = "NextToken",
        maximum_items: int = 5000,
    ) -> list[dict[str, object]]:
        query = dict(arguments)
        tokens: set[str] = set()
        result: list[dict[str, object]] = []
        self.partial_items = []
        for _ in range(self.limits.pages):
            response = self.call(service, method, query)
            values = response.get(result_key)
            if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
                raise ContractError("DIAGNOSTIC_COLLECTION_SHAPE")
            result.extend(cast(list[dict[str, object]], values))
            if self.resolution_only:
                self.partial_items = list(result)
            if (
                len(result) > maximum_items
                or self.discovery_items > DIAGNOSTIC_LIMITS.discovery_items
            ):
                raise ContractError("DIAGNOSTIC_ITEM_LIMIT")
            token = response.get(response_page_field)
            if any(
                response.get(key) not in (None, "", False)
                for key in {"NextToken", "nextToken", "NextMarker", "Marker", "NextPageToken"}
                - {response_page_field}
            ):
                raise ContractError("DIAGNOSTIC_PAGINATION_INCOMPLETE")
            if response.get("IsTruncated") is True and not token:
                raise ContractError("DIAGNOSTIC_PAGINATION_INCOMPLETE")
            if token in (None, ""):
                return result
            if not isinstance(token, str) or token in tokens:
                raise ContractError("DIAGNOSTIC_PAGINATION_INVALID")
            tokens.add(token)
            query[request_page_field] = token
        if self.resolution_only:
            raise DiagnosticCollectionError("RESOLUTION_ENUMERATION_PAGE_LIMIT")
        raise ContractError("DIAGNOSTIC_PAGE_LIMIT")

    def state_bytes(self) -> tuple[bytes, str | None]:
        arguments: dict[str, object] = {
            "Bucket": _DIAGNOSTIC_STATE_BUCKET,
            "Key": _DIAGNOSTIC_STATE_KEY,
            "ExpectedBucketOwner": APPROVED_AWS_ACCOUNT_ID,
        }
        before = self.call("s3", "head_object", arguments)
        version, etag = before.get("VersionId"), before.get("ETag")
        if not isinstance(etag, str) or not etag:
            raise ContractError("DIAGNOSTIC_STATE_VERSION_UNKNOWN")
        query = {**arguments, "IfMatch": etag}
        if isinstance(version, str):
            query["VersionId"] = version
        value = self.call("s3", "get_object", query)
        after = self.call("s3", "head_object", arguments)
        if (version, etag) != (after.get("VersionId"), after.get("ETag")) or (
            value.get("VersionId"),
            value.get("ETag"),
        ) != (version, etag):
            self.reject("DIAGNOSTIC_STATE_DRIFT")
        return cast(bytes, value["state_bytes"]), cast(str | None, version)

    def resolution_discovery(self, category: str, governed: frozenset[str]) -> dict[str, object]:
        """Classify each candidate, preserving partial enumeration and uncertainty."""
        if self.resolution_followup:
            return _followup_discovery(self, category, governed)
        specs = {
            "EC2_NETWORK": ("ec2", "describe_vpcs", "Vpcs", "VpcId"),
            "EC2_SUBNETS": ("ec2", "describe_subnets", "Subnets", "SubnetId"),
            "EC2_ROUTES": ("ec2", "describe_route_tables", "RouteTables", "RouteTableId"),
            "EC2_SECURITY_GROUPS": ("ec2", "describe_security_groups", "SecurityGroups", "GroupId"),
            "ENI": (
                "ec2",
                "describe_network_interfaces",
                "NetworkInterfaces",
                "NetworkInterfaceId",
            ),
            "IAM_ROLES": ("iam", "list_roles", "Roles", "RoleName"),
            "IAM_POLICIES": ("iam", "list_policies", "Policies", "Arn"),
            "KMS": ("kms", "list_keys", "Keys", "KeyId"),
            "S3": ("s3", "list_buckets", "Buckets", "Name"),
        }
        service, method, result_key, identity_key = specs[category]
        arguments: dict[str, object] = (
            {"Scope": "Local"}
            if category == "IAM_POLICIES"
            else {"BucketRegion": APPROVED_AWS_REGION}
            if category == "S3"
            else {}
        )
        token = (
            "Marker"
            if service in {"iam", "kms"}
            else ("ContinuationToken" if service == "s3" else "NextToken")
        )
        complete, failure = True, None
        try:
            rows = self.pages(
                service,
                method,
                arguments,
                result_key=result_key,
                request_page_field=token,
                response_page_field="NextMarker" if service == "kms" else token,
            )
        except ContractError as exc:
            rows, complete, failure = (
                list(self.partial_items),
                False,
                diagnostic_failure_reason(exc),
            )
        results: list[dict[str, object]] = []
        for row in rows:
            resource = row.get(identity_key)
            if not isinstance(resource, str) or not resource or len(resource) > 2048:
                results.append({"resource": None, "classification": "IDENTITY_UNAVAILABLE"})
                continue
            classification = "INSUFFICIENT_OWNERSHIP_EVIDENCE"
            evidence = "OWNERSHIP_NOT_ESTABLISHED"
            if self.fatal_reason is not None:
                results.append(
                    {
                        "resource": resource,
                        "classification": "COLLECTION_BLOCKED",
                        "evidence": "GLOBAL_SAFETY_TERMINATION",
                    }
                )
                continue
            tags = row.get("Tags")
            try:
                if category == "S3" and row.get("BucketRegion") != APPROVED_AWS_REGION:
                    classification = "INSUFFICIENT_REGION_EVIDENCE"
                else:
                    detail = row
                    if category == "IAM_ROLES":
                        detail = cast(
                            dict[str, object],
                            self.call("iam", "get_role", {"RoleName": resource})["Role"],
                        )
                        tags = detail.get("Tags")
                    elif category == "IAM_POLICIES":
                        tag_response = self.call("iam", "list_policy_tags", {"PolicyArn": resource})
                        if tag_response.get("IsTruncated") or tag_response.get("Marker"):
                            raise DiagnosticCollectionError("RESOLUTION_TAG_PAGINATION_INCOMPLETE")
                        tags = tag_response.get("Tags")
                    elif category == "KMS":
                        detail = cast(
                            dict[str, object],
                            self.call("kms", "describe_key", {"KeyId": resource})["KeyMetadata"],
                        )
                        if detail.get("KeyManager") != "AWS":
                            tag_response = self.call(
                                "kms", "list_resource_tags", {"KeyId": resource}
                            )
                            if tag_response.get("Truncated") or tag_response.get("NextMarker"):
                                raise DiagnosticCollectionError(
                                    "RESOLUTION_TAG_PAGINATION_INCOMPLETE"
                                )
                            tags = tag_response.get("Tags")
                    elif category == "S3":
                        tags = self.call(
                            "s3",
                            "get_bucket_tagging",
                            {
                                "Bucket": resource,
                                "ExpectedBucketOwner": APPROVED_AWS_ACCOUNT_ID,
                            },
                        ).get("TagSet")
                    tag_values: dict[str, str] = {}
                    if isinstance(tags, list):
                        for tag in tags:
                            if not isinstance(tag, dict):
                                raise ContractError("RESOLUTION_TAG_SHAPE")
                            key = tag.get("Key", tag.get("TagKey"))
                            value = tag.get("Value", tag.get("TagValue"))
                            if (
                                not isinstance(key, str)
                                or not isinstance(value, str)
                                or key in tag_values
                            ):
                                raise ContractError("RESOLUTION_TAG_SHAPE")
                            tag_values[key] = value
                    if resource in governed or detail.get("Arn") in governed:
                        classification, evidence = "GOVERNED_STATE_MANAGED", "EXACT_STATE_IDENTITY"
                    elif category == "KMS" and detail.get("KeyManager") == "AWS":
                        classification, evidence = "AWS_MANAGED", "KEY_MANAGER_AWS"
                    elif all(
                        tag_values.get(key) == value
                        for key, value in stable_cleanup_tags("sandbox").items()
                    ):
                        classification, evidence = (
                            "PROJECT_OWNED_RESIDUAL",
                            "EXACT_GOVERNED_TAGS_NOT_IN_STATE",
                        )
                    elif (
                        category == "ENI"
                        and row.get("RequesterManaged") is True
                        and (row.get("VpcId") in governed)
                    ):
                        evidence = "REQUESTER_MANAGED_IN_GOVERNED_VPC_OWNERSHIP_UNPROVEN"
                    elif category == "IAM_POLICIES":
                        attached = self.call(
                            "iam", "list_entities_for_policy", {"PolicyArn": resource}
                        )
                        if attached.get("IsTruncated"):
                            complete = False
                        evidence = "ATTACHMENTS_OBSERVED_OWNERSHIP_UNPROVEN"
            except DiagnosticFatalError:
                classification, evidence = "COLLECTION_BLOCKED", "GLOBAL_SAFETY_TERMINATION"
            except (ContractError, KeyError, TypeError) as exc:
                classification, evidence = "COLLECTION_UNRESOLVED", diagnostic_failure_reason(exc)
            results.append(
                {"resource": resource, "classification": classification, "evidence": evidence}
            )
        return {
            "category": category,
            "enumeration_complete": complete,
            "collection_failure": failure,
            "resources": results,
            "unknown_is_orphan": False,
        }

    def resolution_billing(self, kind: str) -> dict[str, object]:
        if self.resolution_followup:
            if kind != "usage":
                self.reject("RESOLUTION_BILLING_SCOPE")
            return _followup_billing(self)
        groupings: dict[str, list[dict[str, str]]] = {
            "account": [],
            "service": [{"Type": "DIMENSION", "Key": "SERVICE"}],
            "usage": [
                {"Type": "DIMENSION", "Key": "SERVICE"},
                {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
            ],
        }
        response = self.call(
            "ce",
            "get_cost_and_usage",
            {
                "TimePeriod": {"Start": RESOLUTION_BILLING_START, "End": RESOLUTION_BILLING_END},
                "Granularity": "DAILY",
                "Metrics": ["UnblendedCost"],
                "GroupBy": groupings[kind],
                "Filter": {
                    "Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [APPROVED_AWS_ACCOUNT_ID]}
                },
            },
        )
        days = response.get("ResultsByTime")
        if not isinstance(days, list):
            raise ContractError("RESOLUTION_BILLING_SHAPE")
        output: list[dict[str, object]] = []
        periods: set[tuple[str, str]] = set()
        expected_periods = {
            (f"2026-09-{day:02d}", f"2026-09-{day + 1:02d}") for day in range(8, 13)
        }
        for day in days:
            if not isinstance(day, dict) or not isinstance(day.get("TimePeriod"), dict):
                raise ContractError("RESOLUTION_BILLING_DAY_SHAPE")
            period = day["TimePeriod"]
            pair = (period.get("Start"), period.get("End"))
            if pair not in expected_periods or pair in periods:
                raise ContractError("RESOLUTION_BILLING_INTERVAL_INVALID")
            periods.add(pair)
            rows = (
                day.get("Groups", [])
                if groupings[kind]
                else [{"Keys": [], "Metrics": day.get("Total")}]
            )
            if not isinstance(rows, list):
                raise ContractError("RESOLUTION_BILLING_GROUP_SHAPE")
            amounts = []
            for row in rows:
                metric = row.get("Metrics", {}).get("UnblendedCost", {})
                amount = Decimal(metric.get("Amount", "NaN"))
                keys = row.get("Keys", [])
                if (
                    metric.get("Unit") != "USD"
                    or not amount.is_finite()
                    or (
                        not isinstance(keys, list)
                        or any(not isinstance(key, str) or len(key) > 256 for key in keys)
                    )
                ):
                    raise ContractError("RESOLUTION_BILLING_AMOUNT_INVALID")
                amounts.append({"keys": keys, "unblended_usd": str(amount)})
            output.append(
                {
                    "start": period.get("Start"),
                    "end": period.get("End"),
                    "estimated": day.get("Estimated"),
                    "amounts": amounts,
                }
            )
        return {
            "view": kind,
            "start_inclusive": RESOLUTION_BILLING_START,
            "end_exclusive": RESOLUTION_BILLING_END,
            "days": output,
            "complete": periods == expected_periods and not bool(response.get("NextPageToken")),
            "missing_day_count": len(expected_periods - periods),
            "attribution": "ACCOUNT_NOT_W5_ATTRIBUTED",
            "w5_incurred_usd": None,
            "billing_lag_seconds": None,
            "headroom_usd": None,
            "overlapping_views_must_not_be_added": True,
        }

    def billing(self, now: datetime, kind: str) -> dict[str, object]:
        start = datetime(2026, 9, 8, tzinfo=UTC).date()
        end = now.astimezone(UTC).date()
        if not 0 < (end - start).days <= 31:
            raise ContractError("DIAGNOSTIC_BILLING_INTERVAL")
        self._billing_end = end.isoformat()
        query: dict[str, object] = {
            "TimePeriod": {"Start": start.isoformat(), "End": end.isoformat()},
            "Granularity": "DAILY",
            "Metrics": ["UnblendedCost"],
            "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
            "Filter": {
                "Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [APPROVED_AWS_ACCOUNT_ID]}
            },
        }
        if kind == "tag_status":
            tags = self.pages(
                "ce",
                "list_cost_allocation_tags",
                {"TagKeys": ["Project"], "MaxResults": 100},
                result_key="CostAllocationTags",
            )
            statuses = {tag.get("Status") for tag in tags}
            if not statuses <= {"Active", "Inactive"}:
                raise ContractError("DIAGNOSTIC_COST_TAG_STATUS")
            return {"project_tag_statuses": sorted(cast(set[str], statuses))}
        if kind not in {"account", "project_tag"}:
            raise ContractError("DIAGNOSTIC_BILLING_KIND")
        output: dict[str, object] = {
            "today_excluded": True,
            "w5_incurred_usd": None,
            "billing_lag_seconds": None,
        }
        for name in (kind,):
            if name == "project_tag":
                query["Filter"] = {
                    "And": [
                        query["Filter"],
                        {"Tags": {"Key": "Project", "Values": ["enterprise-ai-platform"]}},
                    ]
                }
            rows = self.pages(
                "ce",
                "get_cost_and_usage",
                query,
                result_key="ResultsByTime",
                request_page_field="NextPageToken",
                response_page_field="NextPageToken",
            )
            totals: list[dict[str, object]] = []
            for row in rows:
                groups = row.get("Groups")
                period = row.get("TimePeriod")
                estimated = row.get("Estimated")
                if (
                    not isinstance(groups, list)
                    or not isinstance(period, dict)
                    or set(period) != {"Start", "End"}
                    or type(estimated) is not bool
                ):
                    raise ContractError("DIAGNOSTIC_BILLING_RESPONSE")
                try:
                    period_start = datetime.strptime(str(period["Start"]), "%Y-%m-%d").date()
                    period_end = datetime.strptime(str(period["End"]), "%Y-%m-%d").date()
                except ValueError:
                    raise ContractError("DIAGNOSTIC_BILLING_PERIOD") from None
                if (
                    not start <= period_start < period_end <= end
                    or (period_end - period_start).days != 1
                    or period != {"Start": period_start.isoformat(), "End": period_end.isoformat()}
                ):
                    raise ContractError("DIAGNOSTIC_BILLING_PERIOD")
                for group in groups:
                    if not isinstance(group, dict):
                        raise ContractError("DIAGNOSTIC_BILLING_RESPONSE")
                    keys, metrics = group.get("Keys"), group.get("Metrics")
                    if (
                        not isinstance(keys, list)
                        or len(keys) != 1
                        or not isinstance(keys[0], str)
                        or not 1 <= len(keys[0]) <= 128
                        or any(not (char.isalnum() or char in " ._()/+-") for char in keys[0])
                        or not isinstance(metrics, dict)
                    ):
                        raise ContractError("DIAGNOSTIC_BILLING_SERVICE")
                    metric = metrics.get("UnblendedCost")
                    if not isinstance(metric, dict) or metric.get("Unit") != "USD":
                        raise ContractError("DIAGNOSTIC_BILLING_CURRENCY")
                    try:
                        amount = Decimal(str(metric.get("Amount")))
                    except InvalidOperation:
                        raise ContractError("DIAGNOSTIC_BILLING_AMOUNT") from None
                    if not amount.is_finite():
                        raise ContractError("DIAGNOSTIC_BILLING_AMOUNT")
                    totals.append(
                        {
                            "period": {
                                "Start": period_start.isoformat(),
                                "End": period_end.isoformat(),
                            },
                            "service": keys[0],
                            "usd": str(amount),
                            "estimated": estimated,
                        }
                    )
            output[name] = totals
        return output

    def service_role(self) -> dict[str, str]:
        name = "AWSServiceRoleForAmazonOpenSearchService"
        arn = (
            "arn:aws:iam::526338061652:role/aws-service-role/"
            "opensearchservice.amazonaws.com/" + name
        )
        try:
            response = self.call("iam", "get_role", {"RoleName": name})
        except DiagnosticReadError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return {"presence": "ABSENT", "ownership": "OWNER_MANAGED"}
            raise
        role = response.get("Role")
        if not isinstance(role, dict) or role.get("Arn") != arn:
            self.reject("DIAGNOSTIC_SERVICE_ROLE_IDENTITY")
        trust = cast(dict[str, object], role).get("AssumeRolePolicyDocument")
        if not isinstance(trust, dict):
            raise ContractError("DIAGNOSTIC_SERVICE_ROLE_TRUST")
        statements = trust.get("Statement")
        if not isinstance(statements, list) or len(statements) != 1:
            raise ContractError("DIAGNOSTIC_SERVICE_ROLE_TRUST")
        statement = statements[0]
        if not isinstance(statement, dict) or (
            statement.get("Effect") != "Allow"
            or statement.get("Action") not in ("sts:AssumeRole", ["sts:AssumeRole"])
            or statement.get("Principal") != {"Service": "opensearchservice.amazonaws.com"}
            or set(statement) - {"Sid", "Effect", "Action", "Principal"}
        ):
            raise ContractError("DIAGNOSTIC_SERVICE_ROLE_TRUST")
        attached = self.pages(
            "iam",
            "list_attached_role_policies",
            {"RoleName": name},
            result_key="AttachedPolicies",
            request_page_field="Marker",
            response_page_field="Marker",
        )
        policy_arn = "arn:aws:iam::aws:policy/aws-service-role/AmazonOpenSearchServiceRolePolicy"
        if len(attached) != 1 or attached[0].get("PolicyArn") != policy_arn:
            raise ContractError("DIAGNOSTIC_SERVICE_ROLE_PERMISSION_POLICY")
        policy = self.call("iam", "get_policy", {"PolicyArn": policy_arn}).get("Policy")
        if not isinstance(policy, dict) or not isinstance(policy.get("DefaultVersionId"), str):
            raise ContractError("DIAGNOSTIC_SERVICE_ROLE_POLICY_VERSION")
        version = self.call(
            "iam",
            "get_policy_version",
            {
                "PolicyArn": policy_arn,
                "VersionId": policy["DefaultVersionId"],
            },
        ).get("PolicyVersion")
        if not isinstance(version, dict) or not isinstance(version.get("Document"), dict):
            raise ContractError("DIAGNOSTIC_SERVICE_ROLE_POLICY_DOCUMENT")
        inline = self.call("iam", "list_role_policies", {"RoleName": name})
        if inline.get("PolicyNames") != [] or inline.get("IsTruncated") is not False:
            raise ContractError("DIAGNOSTIC_SERVICE_ROLE_INLINE_POLICY")
        return {
            "presence": "PRESENT",
            "ownership": "OWNER_MANAGED",
            "trust": "EXACT_SERVICE",
            "permissions": "AWS_MANAGED_SERVICE_ROLE_POLICY",
        }

    def caller_authorization_structure(self) -> dict[str, object]:
        """Read only the caller's actual policy dependencies; disclose no documents."""
        user = self.call("iam", "get_user", {"UserName": "finopsinfra"}).get("User")
        if not isinstance(user, dict) or user.get("Arn") != APPROVED_CALLER_ARN:
            self.reject("DIAGNOSTIC_CALLER_POLICY_IDENTITY")
        groups = self.pages(
            "iam",
            "list_groups_for_user",
            {"UserName": "finopsinfra"},
            result_key="Groups",
            request_page_field="Marker",
            response_page_field="Marker",
            maximum_items=DIAGNOSTIC_LIMITS.caller_groups,
        )
        attached: set[str] = set()
        inline_count = 0
        principals = [("user", "UserName", "finopsinfra")]
        for group in groups:
            name = group.get("GroupName")
            if not isinstance(name, str):
                raise ContractError("DIAGNOSTIC_CALLER_GROUP_SHAPE")
            principals.append(("group", "GroupName", name))
        for kind, field, name in principals:
            rows = self.pages(
                "iam",
                f"list_attached_{kind}_policies",
                {field: name},
                result_key="AttachedPolicies",
                request_page_field="Marker",
                response_page_field="Marker",
            )
            for row in rows:
                arn = row.get("PolicyArn")
                if not isinstance(arn, str):
                    raise ContractError("DIAGNOSTIC_POLICY_DEPENDENCY_SHAPE")
                attached.add(arn)
            for policy_name in self._policy_names(f"list_{kind}_policies", {field: name}):
                document = self.call(
                    "iam",
                    f"get_{kind}_policy",
                    {
                        field: name,
                        "PolicyName": policy_name,
                    },
                ).get("PolicyDocument")
                self._policy_structure(document)
                inline_count += 1
        boundary = cast(dict[str, object], user).get("PermissionsBoundary")
        if isinstance(boundary, dict):
            arn = boundary.get("PermissionsBoundaryArn")
            if not isinstance(arn, str):
                raise ContractError("DIAGNOSTIC_PERMISSIONS_BOUNDARY_SHAPE")
            attached.add(arn)
        for arn in sorted(attached):
            metadata = self.call("iam", "get_policy", {"PolicyArn": arn}).get("Policy")
            version = metadata.get("DefaultVersionId") if isinstance(metadata, dict) else None
            if not isinstance(version, str):
                raise ContractError("DIAGNOSTIC_POLICY_VERSION")
            policy = self.call(
                "iam",
                "get_policy_version",
                {
                    "PolicyArn": arn,
                    "VersionId": version,
                },
            ).get("PolicyVersion")
            self._policy_structure(policy.get("Document") if isinstance(policy, dict) else None)
        return {
            "policy_documents": "STRUCTURALLY_READ_IN_MEMORY",
            "groups": len(groups),
            "managed_policies": len(attached),
            "inline_policies": inline_count,
            "permissions_boundary_present": boundary is not None,
            "scp_effect": "NOT_ESTABLISHED",
            "live_authorization": "NOT_ESTABLISHED",
        }

    @staticmethod
    def _policy_structure(document: object) -> None:
        if not isinstance(document, dict) or not isinstance(
            document.get("Statement"),
            (list, dict),
        ):
            raise ContractError("DIAGNOSTIC_POLICY_STRUCTURE")

    def _policy_names(self, method: str, arguments: dict[str, object]) -> tuple[str, ...]:
        names: set[str] = set()
        markers: set[str] = set()
        query = dict(arguments)
        for _ in range(DIAGNOSTIC_LIMITS.pages):
            response = self.call("iam", method, query)
            values = response.get("PolicyNames")
            if not isinstance(values, list) or any(not isinstance(item, str) for item in values):
                raise ContractError("DIAGNOSTIC_POLICY_NAMES")
            if names.intersection(values) or len(set(values)) != len(values):
                raise ContractError("DIAGNOSTIC_POLICY_NAMES_DUPLICATED")
            names.update(values)
            if len(names) > DIAGNOSTIC_LIMITS.items_per_query:
                raise ContractError("DIAGNOSTIC_ITEM_LIMIT")
            if response.get("IsTruncated") is False:
                return tuple(sorted(names))
            marker = response.get("Marker")
            if not isinstance(marker, str) or not marker or marker in markers:
                raise ContractError("DIAGNOSTIC_POLICY_PAGINATION")
            markers.add(marker)
            query["Marker"] = marker
        raise ContractError("DIAGNOSTIC_PAGE_LIMIT")

    def bind_authorization_targets(self, log_names: tuple[str, ...], domain_name: str) -> None:
        if len(log_names) != 4 or len(set(log_names)) != 4 or not domain_name:
            raise ContractError("DIAGNOSTIC_AUTHORIZATION_TARGETS")
        expected_names = tuple(
            "/aws/OpenSearchService/domains/enterprise-ai-sandbox/" + suffix
            for suffix in (
                "application-logs",
                "audit-logs",
                "index-slow-logs",
                "search-slow-logs",
            )
        )
        if log_names != expected_names or domain_name != "enterprise-ai-sandbox":
            raise ContractError("DIAGNOSTIC_LOG_NAME_SCOPE")
        logs = tuple(
            "arn:aws:logs:ap-southeast-1:526338061652:log-group:" + name for name in log_names
        )
        self._simulation_targets = {
            action: logs
            for action in (
                "logs:CreateLogGroup",
                "logs:TagResource",
                "logs:AssociateKmsKey",
                "logs:PutRetentionPolicy",
            )
        }
        self._simulation_targets.update(
            {
                "logs:PutResourcePolicy": ("*",),
                "es:CreateDomain": (
                    "arn:aws:es:ap-southeast-1:526338061652:domain/" + domain_name,
                ),
                "iam:CreateServiceLinkedRole": (
                    "arn:aws:iam::526338061652:role/aws-service-role/"
                    "opensearchservice.amazonaws.com/AWSServiceRoleForAmazonOpenSearchService",
                ),
            }
        )

    def simulate(self, action: str) -> dict[str, object]:
        targets = self._simulation_targets.get(action)
        if targets is None:
            raise ContractError("DIAGNOSTIC_SIMULATION_NOT_BOUND")
        arguments: dict[str, object] = {
            "PolicySourceArn": APPROVED_CALLER_ARN,
            "ActionNames": [action],
            "ResourceArns": list(targets),
        }
        if action == "iam:CreateServiceLinkedRole":
            arguments["ContextEntries"] = [
                {
                    "ContextKeyName": "iam:AWSServiceName",
                    "ContextKeyValues": ["opensearchservice.amazonaws.com"],
                    "ContextKeyType": "string",
                }
            ]
        rows = self.pages(
            "iam",
            "simulate_principal_policy",
            arguments,
            result_key="EvaluationResults",
            request_page_field="Marker",
            response_page_field="Marker",
        )
        normalized = normalize_simulation_results(rows, action, targets, complete=True)
        normalized["decisions"] = [
            row["decision"] for row in cast(list[dict[str, object]], normalized["findings"])
        ]
        normalized["missing_context_count"] = len(cast(list[str], normalized["missing_context"]))
        return normalized

    def cloudtrail_failures(
        self,
        names: tuple[str, ...],
        event_names: tuple[str, ...],
        kms_identities: frozenset[str],
    ) -> dict[str, object]:
        if len(names) != 4 or len(set(names)) != 4:
            raise ContractError("DIAGNOSTIC_LOG_TARGETS_REQUIRED")
        findings: list[dict[str, str]] = []
        seen: set[str] = set()
        if not event_names or not set(event_names) <= _DIAGNOSTIC_EVENTS:
            raise ContractError("DIAGNOSTIC_EVENT_SELECTION")
        for event_name in sorted(event_names):
            rows = self.pages(
                "cloudtrail",
                "lookup_events",
                {
                    "LookupAttributes": [
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    "StartTime": datetime(2026, 9, 10, 7, 40, tzinfo=UTC),
                    "EndTime": datetime(2026, 9, 10, 8, 40, tzinfo=UTC),
                    "MaxResults": 50,
                },
                result_key="Events",
                maximum_items=500,
            )
            for row in rows:
                event_id, encoded = row.get("EventId"), row.get("CloudTrailEvent")
                if not isinstance(event_id, str) or not isinstance(encoded, str):
                    raise ContractError("DIAGNOSTIC_EVENT_SHAPE")
                if event_id in seen:
                    continue
                seen.add(event_id)
                event = decode_json_strict(encoded.encode(), maximum_bytes=1024 * 1024)
                if not isinstance(event, dict):
                    raise ContractError("DIAGNOSTIC_EVENT_SHAPE")
                identity = event.get("userIdentity")
                if not isinstance(identity, dict) or identity.get("arn") != APPROVED_CALLER_ARN:
                    continue
                if event.get("awsRegion") != APPROVED_AWS_REGION:
                    self.reject("DIAGNOSTIC_EVENT_REGION")
                if (
                    event.get("eventName") != event_name
                    or event.get("recipientAccountId") != APPROVED_AWS_ACCOUNT_ID
                ):
                    self.reject("DIAGNOSTIC_EVENT_IDENTITY")
                event_time = parse_utc_timestamp(
                    str(event.get("eventTime")), "CloudTrail event time"
                )
                if not (
                    datetime(2026, 9, 10, 7, 40, tzinfo=UTC)
                    <= event_time
                    <= datetime(2026, 9, 10, 8, 40, tzinfo=UTC)
                ):
                    self.reject("DIAGNOSTIC_EVENT_INTERVAL")
                event_timestamp = event_time.isoformat().replace("+00:00", "Z")
                parameters = event.get("requestParameters")
                if not isinstance(parameters, dict):
                    continue
                resource = ""
                log_name = parameters.get("logGroupName")
                if event_name in {"CreateLogGroup", "AssociateKmsKey"} and log_name in names:
                    resource = "LOG_GROUP_" + str(names.index(cast(str, log_name)))
                elif event_name == "PutResourcePolicy" and parameters.get("policyName") == (
                    "enterprise-ai-sandbox-opensearch-log-delivery"
                ):
                    resource = "OPENSEARCH_LOG_RESOURCE_POLICY"
                elif (
                    event_name == "CreateDomain"
                    and parameters.get("domainName") == "enterprise-ai-sandbox"
                ):
                    resource = "OPENSEARCH_DOMAIN"
                elif (
                    event_name == "CreateServiceLinkedRole"
                    and parameters.get(
                        "aWSServiceName",
                        parameters.get("awsServiceName"),
                    )
                    == "opensearchservice.amazonaws.com"
                ):
                    resource = "OWNER_MANAGED_SERVICE_ROLE"
                elif event_name == "CreateGrant" and parameters.get("keyId") in kms_identities:
                    resource = "GOVERNED_KMS_KEY"
                if not resource:
                    continue
                if not event.get("errorCode"):
                    findings.append(
                        {
                            "event": event_name,
                            "event_time": event_timestamp,
                            "classification": "EVENT_WITHOUT_ERROR",
                            "caller": "MATCH",
                            "resource": resource,
                        }
                    )
                    continue
                message = str(event.get("errorMessage", "")).casefold()
                classification = "INDETERMINATE"
                for token, category in (
                    ("logs:tagresource", "MISSING_TAG_AUTHORIZATION"),
                    ("logs:associatekmskey", "MISSING_KMS_ASSOCIATION_AUTHORIZATION"),
                    ("logs:putretentionpolicy", "MISSING_RETENTION_AUTHORIZATION"),
                ):
                    if token in message and ("denied" in message or "not authorized" in message):
                        classification = category
                if (
                    classification == "INDETERMINATE"
                    and "kms" in message
                    and ("not authorized" in message or "access denied" in message)
                ):
                    classification = "KMS_SERVICE_AUTHORIZATION_FAILURE"
                findings.append(
                    {
                        "event": event_name,
                        "event_time": event_timestamp,
                        "classification": classification,
                        "caller": "MATCH",
                        "resource": resource,
                    }
                )
        return {
            "failures": findings,
            "historical_cause": "OWNER_RECONCILIATION_REQUIRED",
            "outside_interval": "NOT_ASSESSED",
        }


def discover_project_resources(
    provider: Boto3AwsInventoryProvider,
    client_factory: Callable[[str, str], object],
    bundle: NativeScanBundle,
) -> tuple[tuple[str, str], ...]:
    """Operational discovery still requires the complete service inventory."""
    return _discover_project_resources(provider, client_factory, bundle, set(_DISCOVERY_COVERAGE))


def discover_diagnostic_scan(
    provider: Boto3AwsInventoryProvider,
    client_factory: Callable[[str, str], object],
    bundle: NativeScanBundle,
) -> tuple[tuple[str, str], ...]:
    """A single diagnostic partition is never proof of overall cleanliness."""
    if len(bundle.scans) != 1 or bundle.scans[0].coverage not in _DISCOVERY_COVERAGE:
        raise ContractError("DIAGNOSTIC_DISCOVERY_PARTITION_INVALID")
    scan = bundle.scans[0]
    if (
        scan.maximum_pages > DIAGNOSTIC_LIMITS.pages
        or scan.maximum_items > DIAGNOSTIC_LIMITS.items_per_query
    ):
        raise ContractError("DIAGNOSTIC_DISCOVERY_LIMIT_INVALID")
    return _discover_project_resources(provider, client_factory, bundle, {scan.coverage})


def diagnostic_discovery_coverage() -> frozenset[str]:
    return frozenset(_DISCOVERY_COVERAGE)


def _discover_project_resources(
    provider: Boto3AwsInventoryProvider,
    client_factory: Callable[[str, str], object],
    bundle: NativeScanBundle,
    required_coverage: set[str],
) -> tuple[tuple[str, str], ...]:
    """Share collection without weakening the operational all-services gate."""
    if {scan.coverage for scan in bundle.scans} != required_coverage or len(bundle.scans) != len(
        required_coverage
    ):
        raise ContractError("NATIVE_DISCOVERY_COVERAGE_INCOMPLETE")
    found: set[tuple[str, str]] = set()
    excluded = {
        native_identity_key(service, identity): classification
        for service, identity, classification in bundle.excluded_identities
    }
    if len(excluded) != len(bundle.excluded_identities) or any(
        classification not in {"SHARED", "OWNER_MANAGED", "UNRELATED"}
        for classification in excluded.values()
    ):
        raise ContractError("NATIVE_DISCOVERY_EXCLUSIONS_INVALID")
    for scan in bundle.scans:
        if (scan.service, scan.method) != _DISCOVERY_COVERAGE[scan.coverage]:
            raise ContractError("NATIVE_DISCOVERY_METHOD_MISMATCH")
        if not 1 <= scan.maximum_pages <= 100 or not 1 <= scan.maximum_items <= 10000:
            raise ContractError("NATIVE_DISCOVERY_LIMIT_INVALID")
        arguments = decode_json_strict(scan.arguments_json.encode())
        if not isinstance(arguments, dict):
            raise ContractError("NATIVE_DISCOVERY_ARGUMENTS_INVALID")
        allowed_arguments: dict[str, object] = {}
        if scan.coverage == "IAM_POLICIES":
            allowed_arguments = {"Scope": "Local"}
        elif scan.coverage == "SECRETS_MANAGER":
            allowed_arguments = {"IncludePlannedDeletion": True}
        elif scan.coverage == "CLOUDWATCH_ALARMS":
            allowed_arguments = {"AlarmTypes": ["MetricAlarm", "CompositeAlarm"]}
        if arguments not in ({}, allowed_arguments):
            raise ContractError("NATIVE_DISCOVERY_FILTER_WOULD_REDUCE_COVERAGE")
        if (
            scan.service == "iam"
            and scan.method == "list_policies"
            and arguments != {"Scope": "Local"}
        ):
            raise ContractError("NATIVE_DISCOVERY_POLICY_SCOPE_REQUIRED")
        _validate_native_scope(scan.service, arguments)
        provider.verify_identity()
        client = client_factory(scan.service, APPROVED_AWS_REGION)
        method = getattr(client, scan.method, None)
        if not callable(method):
            raise ContractError("NATIVE_DISCOVERY_ADAPTER_UNAVAILABLE")
        tokens: set[str] = set()
        identities: set[str] = set()
        complete = False
        for _ in range(scan.maximum_pages):
            try:
                response = method(**arguments)
                if not isinstance(response, dict):
                    raise ContractError("NATIVE_DISCOVERY_RESPONSE_INVALID")
                items: object
                if scan.coverage == "CLOUDWATCH_ALARMS":
                    metrics = response.get("MetricAlarms", [])
                    composites = response.get("CompositeAlarms", [])
                    if not isinstance(metrics, list) or not isinstance(composites, list):
                        raise ContractError("DIAGNOSTIC_ALARM_COVERAGE_INCOMPLETE")
                    items = metrics + composites
                else:
                    items = _native_field(response, scan.result_key)
                if not isinstance(response, dict) or not isinstance(items, list):
                    raise ContractError("NATIVE_DISCOVERY_RESPONSE_INVALID")
                for item in items:
                    identity = (
                        item
                        if isinstance(item, str) and scan.identity_key == ""
                        else _native_field(item, scan.identity_key)
                    )
                    if not isinstance(identity, str) or not identity or identity in identities:
                        raise ContractError("NATIVE_DISCOVERY_IDENTITY_INVALID")
                    identities.add(identity)
                    if len(identities) > scan.maximum_items:
                        raise ContractError("NATIVE_DISCOVERY_ITEM_LIMIT")
                    _validate_native_scope(scan.service, identity)
                    if scan.service == "s3" and isinstance(client, _DiagnosticClient):
                        bucket_region = item.get("BucketRegion") if isinstance(item, dict) else None
                        if bucket_region is not None and not isinstance(bucket_region, str):
                            raise ContractError("NATIVE_DISCOVERY_BUCKET_REGION_MALFORMED")
                        if bucket_region and bucket_region != APPROVED_AWS_REGION:
                            # Enumeration is global; resource reads remain regional.
                            continue
                        if (
                            bucket_region != APPROVED_AWS_REGION
                            and identity not in client.session._verified_regional_buckets
                        ):
                            raise ContractError("NATIVE_DISCOVERY_BUCKET_REGION_UNVERIFIED")
                    if scan.detail_method is not None:
                        if (
                            scan.detail_method not in _READ_METHODS.get(scan.service, frozenset())
                            or not scan.detail_argument
                            or not scan.detail_identity_key
                        ):
                            raise ContractError("NATIVE_DISCOVERY_DETAIL_INVALID")
                        item = getattr(client, scan.detail_method)(
                            **{scan.detail_argument: identity}
                        )
                        resolved = _native_field(item, scan.detail_identity_key)
                        if not isinstance(resolved, str) or not resolved:
                            raise ContractError("NATIVE_DISCOVERY_DETAIL_IDENTITY_INVALID")
                        identity = resolved
                        _validate_native_scope(scan.service, identity)
                    try:
                        tags: object = (
                            None
                            if scan.tag_method is not None
                            else _native_field(item, scan.tags_key)
                        )
                    except ContractError as exc:
                        if str(exc) == "NATIVE_ASSERTION_FIELD_UNAVAILABLE":
                            raise ContractError(
                                "NATIVE_DISCOVERY_OWNERSHIP_TAGS_UNAVAILABLE"
                            ) from None
                        raise
                    if scan.tag_method is not None:
                        if (
                            scan.tag_method not in _READ_METHODS.get(scan.service, frozenset())
                            or not scan.tag_argument
                            or not scan.tag_result_key
                        ):
                            raise ContractError("NATIVE_DISCOVERY_TAG_METHOD_INVALID")
                        tag_identity = (
                            _native_field(item, scan.tag_identity_key)
                            if scan.tag_identity_key
                            else identity
                        )
                        if not isinstance(tag_identity, str) or not tag_identity:
                            raise ContractError("NATIVE_DISCOVERY_TAG_IDENTITY_INVALID")
                        query: dict[str, object] = {
                            scan.tag_argument: [tag_identity]
                            if (scan.service, scan.tag_method) == ("elbv2", "describe_tags")
                            else tag_identity
                        }
                        if scan.coverage == "GLUE":
                            if ":" in tag_identity or "/" in tag_identity:
                                raise ContractError("DIAGNOSTIC_GLUE_JOB_NAME_INVALID")
                            identity = (
                                "arn:aws:glue:ap-southeast-1:526338061652:job/" + tag_identity
                            )
                            query[scan.tag_argument] = identity
                        if scan.service == "s3":
                            query["ExpectedBucketOwner"] = APPROVED_AWS_ACCOUNT_ID
                        try:
                            tag_response = getattr(client, scan.tag_method)(**query)
                            if not isinstance(tag_response, dict):
                                raise ContractError("NATIVE_TAG_RESPONSE_INVALID")
                            if any(
                                tag_response.get(key) not in (None, "", False)
                                for key in (
                                    "NextToken",
                                    "nextToken",
                                    "NextMarker",
                                    "Marker",
                                    "IsTruncated",
                                )
                            ):
                                raise ContractError("NATIVE_TAG_PAGINATION_INCOMPLETE")
                            tags = _native_field(tag_response, scan.tag_result_key)
                        except DiagnosticFatalError:
                            raise
                        except Exception as exc:
                            response_error = getattr(exc, "response", {})
                            error = (
                                response_error.get("Error", {})
                                if isinstance(response_error, dict)
                                else {}
                            )
                            if (scan.service, scan.tag_method) != ("s3", "get_bucket_tagging") or (
                                not isinstance(error, dict) or error.get("Code") != "NoSuchTagSet"
                            ):
                                if isinstance(
                                    exc, (DiagnosticReadError, DiagnosticCollectionError)
                                ):
                                    raise
                                raise ContractError(
                                    "NATIVE_DISCOVERY_TAG_READ_INDETERMINATE"
                                ) from exc
                            tags = {}
                    if isinstance(tags, list):
                        tags = _native_field({"Tags": tags}, "Tags")
                    if not isinstance(tags, dict):
                        raise ContractError("NATIVE_DISCOVERY_OWNERSHIP_INDETERMINATE")
                    if all(
                        tags.get(key) == value
                        for key, value in stable_cleanup_tags("sandbox").items()
                    ):
                        if native_identity_key(scan.service, identity) in excluded:
                            raise ContractError("PROJECT_RESOURCE_CANNOT_BE_EXCLUDED")
                        parse_utc_timestamp(str(tags.get("ExpiresAt", "")), "discovery expiry")
                        found.add(native_identity_key(scan.service, identity))
                    elif not tags and native_identity_key(scan.service, identity) not in excluded:
                        raise ContractError("UNTAGGED_RESOURCE_OWNERSHIP_UNCLASSIFIED")
                    elif tags.get("Project") == stable_cleanup_tags("sandbox")["Project"]:
                        raise ContractError("PROJECT_RESOURCE_TAGS_INCOMPLETE")
                token = response.get(scan.response_token) if scan.response_token else None
                unexpected = any(
                    response.get(key) not in (None, "", False)
                    for key in {
                        "NextToken",
                        "nextToken",
                        "NextMarker",
                        "Marker",
                        "PaginationToken",
                        "LastEvaluatedTableName",
                        "ContinuationToken",
                    }
                    - {scan.response_token}
                )
                if unexpected or (response.get("IsTruncated") is True and not token):
                    raise ContractError("NATIVE_DISCOVERY_PAGINATION_INCOMPLETE")
                if token in (None, ""):
                    complete = True
                    break
                if not isinstance(token, str) or token in tokens or scan.request_token is None:
                    raise ContractError("NATIVE_DISCOVERY_PAGINATION_INVALID")
                tokens.add(token)
                arguments[scan.request_token] = token
            except ContractError as exc:
                if isinstance(client, _DiagnosticClient) and str(exc) in {
                    "NATIVE_ARN_PARTITION_INVALID",
                    "NATIVE_ARN_SCOPE_MISMATCH",
                    "NATIVE_S3_ARN_SCOPE_INVALID",
                }:
                    client.session.reject("DIAGNOSTIC_NATIVE_IDENTITY_OR_ROUTING")
                raise
            except Exception as exc:
                raise ContractError("NATIVE_DISCOVERY_INDETERMINATE") from exc
        if not complete:
            raise ContractError("NATIVE_DISCOVERY_PAGE_LIMIT")
    return tuple(sorted(found))


def native_identity_key(service: str, identity: str) -> tuple[str, str]:
    """Join tag discovery to native reads using parsed identities, never name resemblance."""
    _validate_native_scope(service, identity)
    if not identity.startswith("arn:"):
        return service, identity
    parts = identity.split(":", 5)
    if len(parts) != 6:
        raise ContractError("NATIVE_IDENTITY_ARN_MALFORMED")
    arn_service, resource = parts[2], parts[5]
    expected_service = {
        "es": "opensearch",
        "elasticloadbalancing": "elbv2",
        "states": "stepfunctions",
    }.get(arn_service, arn_service)
    if service not in {expected_service, "resourcegroupstaggingapi"}:
        raise ContractError("NATIVE_IDENTITY_SERVICE_MISMATCH")
    # Selectors below match native API identities; the original ARN remains in evidence.
    if arn_service in {"ec2", "kms", "dynamodb", "ecr", "es"}:
        _, separator, native = resource.partition("/")
        if not separator or not native:
            raise ContractError("NATIVE_IDENTITY_RESOURCE_MALFORMED")
        return expected_service, native
    if arn_service == "s3":
        if "/" in resource:
            raise ContractError("NATIVE_DISCOVERY_EXPECTS_BUCKET_IDENTITY")
        return "s3", resource
    if arn_service == "logs" and resource.startswith("log-group:"):
        return "logs", resource.removeprefix("log-group:").removesuffix(":*")
    return expected_service, identity


_ABSENCE_CODES: Mapping[tuple[str, str], frozenset[str]] = {
    ("logs", "describe_log_groups"): frozenset({"ResourceNotFoundException"}),
    ("opensearch", "describe_domain"): frozenset({"ResourceNotFoundException"}),
    ("kms", "describe_key"): frozenset({"NotFoundException"}),
    ("iam", "get_role"): frozenset({"NoSuchEntity"}),
    ("dynamodb", "describe_table"): frozenset({"ResourceNotFoundException"}),
    ("ecr", "describe_repositories"): frozenset({"RepositoryNotFoundException"}),
    ("s3", "head_bucket"): frozenset({"404", "NoSuchBucket"}),
    ("s3", "head_object"): frozenset({"404", "NoSuchKey", "NotFound"}),
}


@dataclass(frozen=True)
class NativeProbeResult:
    """Path-only identity classification, never raw AWS response content."""

    address: str
    resource_type: str
    presence: str
    reason_code: str
    pages: int
    matched_count: int
    configuration: Outcome = Outcome.NOT_RUN
    remote_version: str | None = None
    key_state: str | None = None
    scheduled_deletion_at: str | None = None
    mismatches: tuple[tuple[str, str], ...] = ()
    comparison_notes: tuple[tuple[str, str], ...] = ()


def _lifecycle_mismatch_paths(actual: object, expected: object) -> tuple[tuple[str, str], ...]:
    """Bounded schema paths only; never emit rule IDs, prefixes, tags or values."""
    fields = {
        "ID",
        "Status",
        "Filter",
        "Prefix",
        "And",
        "Tags",
        "Key",
        "Value",
        "ObjectSizeGreaterThan",
        "ObjectSizeLessThan",
        "Expiration",
        "Days",
        "Date",
        "ExpiredObjectDeleteMarker",
        "Transitions",
        "StorageClass",
        "NoncurrentVersionTransitions",
        "NoncurrentVersionExpiration",
        "NoncurrentDays",
        "NewerNoncurrentVersions",
        "AbortIncompleteMultipartUpload",
        "DaysAfterInitiation",
    }
    differences: set[tuple[str, str]] = set()

    def walk(left: object, right: object, path: str, depth: int) -> None:
        if len(differences) >= 64 or depth > 8:
            differences.add(("Rules", "MISMATCH_DETAIL_LIMIT"))
            return
        if type(left) is not type(right):
            differences.add((path, "TYPE_MISMATCH"))
        elif isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                if len(differences) >= 64:
                    differences.add(("Rules", "MISMATCH_DETAIL_LIMIT"))
                    break
                child = path + "." + (key if key in fields else "<unrecognized-field>")
                if key not in left:
                    differences.add((child, "MISSING_FIELD"))
                elif key not in right:
                    differences.add((child, "UNEXPECTED_FIELD"))
                else:
                    walk(left[key], right[key], child, depth + 1)
        elif isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                differences.add((path, "ITEM_COUNT_MISMATCH"))
            for index, (observed, approved) in enumerate(zip(left[:64], right[:64], strict=False)):
                walk(observed, approved, f"{path}[{index}]", depth + 1)
            if max(len(left), len(right)) > 64:
                differences.add((path, "MISMATCH_DETAIL_LIMIT"))
        elif left != right:
            differences.add((path, "VALUE_MISMATCH"))

    walk(native_unordered_value(actual), native_unordered_value(expected), "Rules", 0)
    return tuple(sorted(differences))


def _diagnostic_lifecycle_comparison_item(
    spec: NativeReadSpec, item: dict[str, object], expected_fields: Mapping[str, object]
) -> dict[str, object]:
    """Share all-object filter equivalence only within each exact approved rule set."""
    from .aws_inventory import diagnostic_resource_profile

    scopes = {
        "aws_s3_bucket_lifecycle_configuration.terraform_state": "bootstrap",
        "module.storage.aws_s3_bucket_lifecycle_configuration.this": "platform",
    }
    if (
        spec.address not in scopes
        or spec.resource_type != "aws_s3_bucket_lifecycle_configuration"
        or (spec.service, spec.method) != ("s3", "get_bucket_lifecycle_configuration")
    ):
        return item
    target = next(
        target
        for target in diagnostic_resource_profile(scopes[spec.address]).targets
        if target.address == spec.address
    )
    approved_fields = next(
        decode_json_strict(assertion.expected_fields_json.encode())
        for assertion in target.assertions
        if assertion.category == "CONFIGURATION"
    )
    if not isinstance(approved_fields, dict):
        return item
    approved = approved_fields.get("Rules.@unordered")
    if canonical_json_bytes(native_unordered_value(expected_fields.get("Rules.@unordered"))) != (
        canonical_json_bytes(native_unordered_value(approved))
    ):
        return item
    rules = item.get("Rules")
    if not isinstance(rules, list) or not isinstance(approved, list):
        return item
    if len(rules) != len(approved) or any(not isinstance(rule, dict) for rule in rules):
        return item
    candidates = []
    for rule in rules:
        candidate = {**rule, "Filter": {}} if rule.get("Filter") == {"Prefix": ""} else rule
        # Exact identity/actions/durations/predicates; duplicates still fail the final comparison.
        if any(canonical_json_bytes(candidate) == canonical_json_bytes(row) for row in approved):
            candidates.append(candidate)
        else:
            candidates.append(rule)
    return item if candidates == rules else {**item, "Rules": candidates}


def _lifecycle_prefix_notes(item: Mapping[str, object]) -> tuple[tuple[str, str], ...]:
    """Classify live values in memory; never retain a prefix or rule identifier."""
    rules = item.get("Rules")
    if not isinstance(rules, list):
        return (("Rules", "PREFIX_UNAVAILABLE"),)
    notes = []
    for index, rule in enumerate(rules[:64]):
        value = rule.get("Filter") if isinstance(rule, dict) else None
        classification = "PREFIX_UNAVAILABLE"
        if isinstance(value, dict):
            if value == {}:
                classification = "EMPTY_FILTER"
            elif "Prefix" in value:
                prefix = value["Prefix"]
                classification = (
                    ("PREFIX_EMPTY" if prefix == "" else "PREFIX_NONEMPTY")
                    if isinstance(prefix, str)
                    else "PREFIX_MALFORMED"
                )
        elif isinstance(rule, dict) and "Filter" in rule:
            classification = "PREFIX_MALFORMED"
        notes.append((f"Rules[{index}].Filter.Prefix", classification))
    return tuple(notes)


def _followup_billing(session: DiagnosticAwsSession) -> dict[str, object]:
    """One logical daily usage query; pagination consumes the same three-request cap."""
    arguments: dict[str, object] = {
        "TimePeriod": {"Start": RESOLUTION_BILLING_START, "End": RESOLUTION_BILLING_END},
        "Granularity": "DAILY",
        "Metrics": ["UnblendedCost"],
        "Filter": {"Dimensions": {"Key": "LINKED_ACCOUNT", "Values": [APPROVED_AWS_ACCOUNT_ID]}},
        "GroupBy": [
            {"Type": "DIMENSION", "Key": "SERVICE"},
            {"Type": "DIMENSION", "Key": "USAGE_TYPE"},
        ],
    }
    merged: dict[str, dict[str, object]] = {}
    seen: set[tuple[str, tuple[str, ...]]] = set()
    complete = False
    for _page in range(3):
        response = session.call("ce", "get_cost_and_usage", arguments)
        days = response.get("ResultsByTime")
        if not isinstance(days, list):
            raise ContractError("RESOLUTION_BILLING_SHAPE")
        for day in days:
            if not isinstance(day, dict) or not isinstance(day.get("TimePeriod"), dict):
                raise ContractError("RESOLUTION_BILLING_DAY_SHAPE")
            period = day["TimePeriod"]
            start, end = period.get("Start"), period.get("End")
            if (
                not isinstance(start, str)
                or not isinstance(end, str)
                or not RESOLUTION_BILLING_START <= start < end <= RESOLUTION_BILLING_END
            ):
                raise ContractError("RESOLUTION_BILLING_INTERVAL_INVALID")
            if (datetime.fromisoformat(end) - datetime.fromisoformat(start)).days != 1 or type(
                day.get("Estimated")
            ) is not bool:
                raise ContractError("RESOLUTION_BILLING_DAY_SHAPE")
            row = merged.setdefault(
                start, {"start": start, "end": end, "estimated": day["Estimated"], "amounts": []}
            )
            if row["end"] != end or row["estimated"] != day["Estimated"]:
                raise ContractError("RESOLUTION_BILLING_DAY_SHAPE")
            groups = day.get("Groups")
            if not isinstance(groups, list):
                raise ContractError("RESOLUTION_BILLING_GROUP_SHAPE")
            for group in groups:
                if (
                    not isinstance(group, dict)
                    or not isinstance(group.get("Keys"), list)
                    or len(group["Keys"]) != 2
                ):
                    raise ContractError("RESOLUTION_BILLING_GROUP_SHAPE")
                keys = group["Keys"]
                if any(
                    not isinstance(key, str)
                    or re.fullmatch(r"[A-Za-z0-9 ()/_.:\-]{1,160}", key) is None
                    for key in keys
                ):
                    raise ContractError("RESOLUTION_BILLING_GROUP_SHAPE")
                metrics = group.get("Metrics")
                cost = metrics.get("UnblendedCost") if isinstance(metrics, dict) else None
                if (
                    not isinstance(cost, dict)
                    or cost.get("Unit") != "USD"
                    or not isinstance(cost.get("Amount"), str)
                ):
                    raise ContractError("RESOLUTION_BILLING_AMOUNT_INVALID")
                try:
                    amount = Decimal(cost["Amount"])
                except InvalidOperation as exc:
                    raise ContractError("RESOLUTION_BILLING_AMOUNT_INVALID") from exc
                identity = (start, tuple(keys))
                if not amount.is_finite() or identity in seen:
                    raise ContractError("RESOLUTION_BILLING_AMOUNT_INVALID")
                seen.add(identity)
                cast(list[dict[str, object]], row["amounts"]).append(
                    {"group": keys, "unblended_usd": str(amount)}
                )
        token = response.get("NextPageToken")
        if token is None:
            complete = len(merged) == 5
            break
        if not isinstance(token, str) or not token:
            raise ContractError("RESOLUTION_BILLING_SHAPE")
        arguments = {**arguments, "NextPageToken": token}
    return {
        "kind": "usage",
        "start_inclusive": RESOLUTION_BILLING_START,
        "end_exclusive": RESOLUTION_BILLING_END,
        "complete": complete,
        "days": [merged[key] for key in sorted(merged)],
        "scope": "ACCOUNT_NOT_W5_ATTRIBUTED",
        "overlapping_views_added": False,
        "later_exposure_and_billing_lag": "UNCOVERED",
    }


def _followup_discovery(
    session: DiagnosticAwsSession, category: str, governed: frozenset[str]
) -> dict[str, object]:
    """Resolve only retained candidates; ownership and dependency relevance are separate."""
    original = session.followup_rows[category]
    if category in {"KMS", "S3"}:
        return {
            "category": category,
            "enumeration_complete": True,
            "collection_failure": None,
            "resources": [{**row, "observation": "RETAINED_NOT_FRESH"} for row in original],
            "unknown_is_orphan": False,
        }
    rows: list[dict[str, object]] = []
    complete = True
    if category in FOLLOWUP_NETWORK:
        method, argument, result_field, key, _count = FOLLOWUP_NETWORK[category]
        values = session.pages(
            "ec2", method, {argument: session.followup_targets[method]}, result_key=result_field
        )
        by_id = {row.get(key): row for row in values}
        if len(by_id) != len(values) or any(
            value not in session.followup_targets[method] for value in by_id
        ):
            session.reject("RESOLUTION_DISCOVERY_IDENTITY")
        for resource in session.followup_targets[method]:
            item = by_id.get(resource)
            result: dict[str, object] = {
                "resource": resource,
                "classification": "INSUFFICIENT_OWNERSHIP_EVIDENCE",
                "relationship": "INSUFFICIENT_EVIDENCE",
                "evidence": "RELATIONSHIP_UNPROVEN",
            }
            if item is None:
                result["evidence"] = "EXACT_TARGET_NOT_RETURNED"
                complete = False
            else:
                owner = item.get("OwnerId")
                if owner is not None and owner != APPROVED_AWS_ACCOUNT_ID:
                    session.reject("RESOLUTION_DISCOVERY_IDENTITY")
                tags = item.get("Tags", [])
                if not isinstance(tags, list) or any(not isinstance(tag, dict) for tag in tags):
                    raise DiagnosticCollectionError("RESOLUTION_TAG_SHAPE")
                tag_values = {tag.get("Key"): tag.get("Value") for tag in tags}
                project = all(
                    tag_values.get(k) == v for k, v in stable_cleanup_tags("sandbox").items()
                )
                vpc = item.get("VpcId")
                if resource in governed:
                    result.update(
                        classification="GOVERNED_STATE_MANAGED",
                        relationship="EXACT_DEPENDENCY",
                        evidence="EXACT_STATE_IDENTITY",
                    )
                elif project:
                    result.update(
                        classification="PROJECT_OWNED_RESIDUAL",
                        relationship="REQUIRES_OWNER_DISPOSITION",
                        evidence="GOVERNED_TAGS_OUTSIDE_STATE",
                    )
                elif category == "ENI":
                    matches = [
                        endpoint
                        for endpoint in session.followup_endpoint_rows.values()
                        if isinstance(endpoint.get("NetworkInterfaceIds"), list)
                        and resource in cast(list[object], endpoint["NetworkInterfaceIds"])
                    ]
                    if len(matches) == 1:
                        endpoint = matches[0]
                        groups = item.get("Groups")
                        approved_groups = endpoint.get("Groups")

                        def ids(value: object) -> set[str] | None:
                            if not isinstance(value, list) or any(
                                not isinstance(x, dict) or not isinstance(x.get("GroupId"), str)
                                for x in value
                            ):
                                return None
                            return {x["GroupId"] for x in value}

                        if (
                            owner == APPROVED_AWS_ACCOUNT_ID
                            and item.get("RequesterManaged") is True
                            and vpc == endpoint.get("VpcId") == session.followup_vpc
                            and isinstance(endpoint.get("SubnetIds"), list)
                            and item.get("SubnetId") in cast(list[object], endpoint["SubnetIds"])
                            and ids(groups) is not None
                            and ids(groups) == ids(approved_groups)
                        ):
                            result.update(
                                classification="SHARED_DEPENDENCY",
                                relationship="EXACT_ENDPOINT_ATTACHMENT",
                                evidence="VPC_SUBNET_GROUPS_AND_ENDPOINT_ID_MATCH",
                            )
                elif (
                    owner == APPROVED_AWS_ACCOUNT_ID
                    and isinstance(vpc, str)
                    and session.followup_vpc is not None
                    and vpc != session.followup_vpc
                ):
                    result.update(
                        classification="OUTSIDE_APPROVED_SANDBOX_NETWORK",
                        relationship="OUTSIDE_NETWORK_DEPENDENCY_SCOPE",
                        evidence="EXACT_DIFFERENT_VPC",
                    )
            rows.append(result)
    elif category == "IAM_ROLES":
        for retained in original:
            name = cast(str, retained["resource"])
            result = {
                "resource": name,
                "classification": "INSUFFICIENT_OWNERSHIP_EVIDENCE",
                "relationship": "INSUFFICIENT_EVIDENCE",
                "evidence": "OWNERSHIP_NOT_ESTABLISHED",
            }
            try:
                role_item = session.call("iam", "get_role", {"RoleName": name}).get("Role")
                if not isinstance(role_item, dict) or role_item.get("RoleName") != name:
                    session.reject("RESOLUTION_ROLE_IDENTITY")
                arn = role_item.get("Arn")
                path = role_item.get("Path")
                if (
                    not isinstance(arn, str)
                    or not isinstance(path, str)
                    or arn != ("arn:aws:iam::" + APPROVED_AWS_ACCOUNT_ID + ":role" + path + name)
                ):
                    session.reject("RESOLUTION_ROLE_IDENTITY")
                if arn in governed or name in governed:
                    result.update(
                        classification="GOVERNED_STATE_MANAGED",
                        relationship="EXACT_DEPENDENCY",
                        evidence="EXACT_STATE_IDENTITY",
                    )
                elif path.startswith("/aws-service-role/") and path.endswith("/"):
                    service = path.removeprefix("/aws-service-role/").removesuffix("/")
                    policy = role_item.get("AssumeRolePolicyDocument")
                    statements = policy.get("Statement") if isinstance(policy, dict) else None
                    if (
                        re.fullmatch(r"[a-z0-9.-]+\.amazonaws\.com", service)
                        and isinstance(statements, list)
                        and len(statements) == 1
                        and statements[0]
                        == {
                            "Effect": "Allow",
                            "Principal": {"Service": service},
                            "Action": "sts:AssumeRole",
                        }
                    ):
                        result.update(
                            classification="AWS_SERVICE_MANAGED",
                            relationship="SHARED_SERVICE_IDENTITY",
                            evidence="EXACT_SERVICE_PATH_AND_TRUST",
                        )
            except DiagnosticFatalError:
                raise
            except (ContractError, KeyError, TypeError) as exc:
                result["evidence"] = diagnostic_failure_reason(exc)
                complete = False
            rows.append(result)
    else:
        policy = cast(str, original[0]["resource"])
        attachments: list[dict[str, str]] = []
        for usage in ("PermissionsPolicy", "PermissionsBoundary"):
            arguments: dict[str, object] = {
                "PolicyArn": policy,
                "PolicyUsageFilter": usage,
                "MaxItems": 100,
            }
            for page in range(3):
                response = session.call("iam", "list_entities_for_policy", arguments)
                for key in ("PolicyRoles", "PolicyUsers", "PolicyGroups"):
                    selected = response.get(key)
                    if not isinstance(selected, list):
                        raise DiagnosticCollectionError("RESOLUTION_DISCOVERY_SHAPE")
                    field = {
                        "PolicyRoles": "RoleName",
                        "PolicyUsers": "UserName",
                        "PolicyGroups": "GroupName",
                    }[key]
                    for item in selected:
                        if not isinstance(item, dict) or not isinstance(item.get(field), str):
                            raise DiagnosticCollectionError("RESOLUTION_DISCOVERY_SHAPE")
                        name = cast(str, item[field])
                        attachments.append(
                            {
                                "kind": key,
                                "usage": usage,
                                "relationship": "GOVERNED_NAME_MATCH"
                                if name in governed
                                else "NOT_PROVEN_SANDBOX_RELATED",
                            }
                        )
                if response.get("IsTruncated") is False:
                    break
                token = response.get("Marker")
                if (
                    response.get("IsTruncated") is not True
                    or not isinstance(token, str)
                    or not token
                ):
                    raise DiagnosticCollectionError("RESOLUTION_DISCOVERY_SHAPE")
                if page == 2:
                    raise DiagnosticCollectionError("RESOLUTION_ENUMERATION_PAGE_LIMIT")
                arguments = {**arguments, "Marker": token}
        rows.append(
            {
                "resource": policy,
                "classification": "INSUFFICIENT_OWNERSHIP_EVIDENCE",
                "relationship": "INSUFFICIENT_EVIDENCE",
                "evidence": "ATTACHMENTS_NOT_OWNERSHIP_PROOF",
                "attachments": attachments,
            }
        )
    return {
        "category": category,
        "enumeration_complete": complete,
        "collection_failure": None,
        "resources": rows,
        "unknown_is_orphan": False,
    }


def _default_endpoint_policy(raw: object) -> bool:
    """Closed, variable-free default only; missing Version has the legacy semantics."""
    try:
        actual = decode_json_strict(raw.encode()) if isinstance(raw, str) else raw
    except ContractError:
        return False
    if not isinstance(actual, dict) or set(actual) not in ({"Statement"}, {"Version", "Statement"}):
        return False
    if actual.get("Version", "2008-10-17") not in ("2008-10-17", "2012-10-17"):
        return False
    statements = actual["Statement"]
    if not isinstance(statements, list) or len(statements) != 1:
        return False
    statement = statements[0]
    return (
        isinstance(statement, dict)
        and set(statement) == {"Effect", "Principal", "Action", "Resource"}
        and statement["Effect"] == "Allow"
        and statement["Principal"] in ("*", {"AWS": "*"}, {"AWS": ["*"]})
        and statement["Action"] in ("*", ["*"])
        and statement["Resource"] in ("*", ["*"])
    )


def _diagnostic_endpoint_comparison_item(
    item: Mapping[str, object], expected_fields: Mapping[str, object]
) -> Mapping[str, object]:
    """Only the exact variable-free default endpoint policy has these equivalent forms."""
    canonical = {
        "Version": "2008-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}],
    }
    if expected_fields.get("PolicyDocument.@diagnostic_policy_sha256") != diagnostic_policy_digest(
        canonical
    ):
        return item
    if not _default_endpoint_policy(item.get("PolicyDocument")):
        return item
    return {**item, "PolicyDocument": canonical_json_bytes(canonical).decode()}


def _endpoint_comparison_details(
    item: Mapping[str, object], expected_fields: Mapping[str, object]
) -> tuple[tuple[tuple[str, str], ...], tuple[tuple[str, str], ...]]:
    """Use trusted assertion paths; never expose native IDs, policy contents or tag values."""
    fields = {
        "VpcId",
        "State",
        "VpcEndpointType",
        "ServiceName",
        "PolicyDocument",
        "PrivateDnsEnabled",
        "SubnetIds",
        "Groups",
        "RouteTableIds",
    }
    differences: list[tuple[str, str]] = []
    notes: list[tuple[str, str]] = []

    def compare(left: object, right: object, path: str, depth: int = 0) -> None:
        if len(differences) >= 64:
            return
        if depth > 8:
            differences.append((path, "MISMATCH_DETAIL_LIMIT"))
            return
        if type(left) is not type(right):
            differences.append((path, "TYPE_MISMATCH"))
        elif isinstance(left, dict) and isinstance(right, dict):
            for key in sorted(set(left) | set(right)):
                child = (
                    path
                    + "."
                    + (key if key in {"GroupId", "GroupName"} else "<unrecognized-field>")
                )
                if key not in left:
                    differences.append((child, "MISSING_FIELD"))
                elif key not in right:
                    differences.append((child, "UNEXPECTED_FIELD"))
                else:
                    compare(left[key], right[key], child, depth + 1)
        elif isinstance(left, list) and isinstance(right, list):
            if len(left) != len(right):
                differences.append((path, "ITEM_COUNT_MISMATCH"))
            for index, (observed, approved) in enumerate(zip(left[:64], right[:64], strict=False)):
                compare(observed, approved, f"{path}[{index}]", depth + 1)
        elif canonical_json_bytes(left) != canonical_json_bytes(right):
            differences.append((path, "CONFIGURATION_DIFFERENCE"))

    for selector, expected in sorted(expected_fields.items()):
        root = selector.split(".")[0]
        path = root if root in fields else "<unrecognized-field>"
        if root not in item:
            differences.append((path, "MISSING_FIELD"))
            continue
        try:
            observed = _native_field(item, selector)
        except ContractError:
            differences.append((path, "MALFORMED_FIELD"))
            continue
        compare(observed, expected, path)
        if (
            canonical_json_bytes(observed) == canonical_json_bytes(expected)
            and selector.endswith(".@unordered")
            and canonical_json_bytes(item[root]) != canonical_json_bytes(expected)
        ):
            notes.append((path, "ORDERING_DIFFERENCE_EQUIVALENT"))
    return tuple(differences), tuple(notes)


class BoundedNativeReader:
    """Allowlisted, capped reads with explicit pagination and no mutation retry."""

    def __init__(
        self,
        provider: Boto3AwsInventoryProvider,
        client_factory: Callable[[str, str], object],
        *,
        diagnostic_details: bool = False,
    ) -> None:
        self._provider = provider
        self._client_factory = client_factory
        self._diagnostic_details = diagnostic_details

    def inspect(
        self,
        spec: NativeReadSpec,
        *,
        expected_fields: Mapping[str, object] | None = None,
    ) -> NativeProbeResult:
        """Verify identity first and classify denied, missing and incomplete separately."""
        if spec.method not in _READ_METHODS.get(spec.service, frozenset()):
            raise ContractError("NATIVE_READ_METHOD_NOT_APPROVED")
        if not 1 <= spec.maximum_pages <= 100 or not 1 <= spec.maximum_items <= 10000:
            raise ContractError("NATIVE_READ_LIMIT_INVALID")
        if not spec.address or not spec.resource_type or not spec.expected_native_identity:
            raise ContractError("NATIVE_READ_TARGET_REQUIRED")
        if (spec.request_token is None) != (spec.response_token is None):
            raise ContractError("NATIVE_PAGINATION_CONTRACT")
        arguments = decode_json_strict(spec.arguments_json.encode("utf-8"), maximum_bytes=65536)
        if not isinstance(arguments, dict):
            raise ContractError("NATIVE_READ_ARGUMENTS_INVALID")
        _validate_native_scope(spec.service, arguments)
        _validate_native_scope(spec.service, spec.expected_native_identity)
        self._provider.verify_identity()
        client = self._client_factory(spec.service, APPROVED_AWS_REGION)
        method = getattr(client, spec.method, None)
        if not callable(method):
            raise ContractError("NATIVE_READ_ADAPTER_UNAVAILABLE")
        tokens: set[str] = set()
        seen: set[str] = set()
        matched = 0
        configuration = Outcome.NOT_RUN
        remote_version: str | None = None
        key_state: str | None = None
        scheduled_deletion_at: str | None = None
        mismatches: tuple[tuple[str, str], ...] = ()
        comparison_notes: tuple[tuple[str, str], ...] = ()
        count = 0
        for page in range(1, spec.maximum_pages + 1):
            try:
                response = method(**arguments)
            except DiagnosticFatalError:
                # Never erase a latched identity/routing stop as an ordinary read error.
                raise
            except Exception as exc:
                error_response = getattr(exc, "response", {})
                error = error_response.get("Error", {}) if isinstance(error_response, dict) else {}
                code = error.get("Code") if isinstance(error, dict) else None
                absent = code in _ABSENCE_CODES.get((spec.service, spec.method), frozenset())
                presence = "ABSENT" if absent and page == 1 else "INDETERMINATE"
                return NativeProbeResult(
                    spec.address,
                    spec.resource_type,
                    presence,
                    "NATIVE_NOT_FOUND" if presence == "ABSENT" else diagnostic_failure_reason(exc),
                    page,
                    matched,
                )
            if not isinstance(response, dict):
                raise ContractError("NATIVE_RESPONSE_MALFORMED")
            values = response if spec.result_key == "" else response.get(spec.result_key)
            if isinstance(values, dict):
                values = [values]
            if not isinstance(values, list):
                return NativeProbeResult(
                    spec.address,
                    spec.resource_type,
                    "INDETERMINATE",
                    "NATIVE_COVERAGE_INCOMPLETE",
                    page,
                    matched,
                )
            count += len(values)
            if count > spec.maximum_items:
                return NativeProbeResult(
                    spec.address,
                    spec.resource_type,
                    "INDETERMINATE",
                    "NATIVE_ITEM_LIMIT",
                    page,
                    matched,
                )
            for item in values:
                identity = (
                    _native_field(item, spec.identity_key)
                    if (isinstance(item, dict) and spec.identity_key)
                    else None
                )
                if spec.identity_key == "" and isinstance(item, dict):
                    # Only resource-scoped APIs may use the request's identity when
                    # the success response does not echo it (for example HeadObject).
                    scope_arguments = {
                        ("s3", "head_object"): "Key",
                        ("s3", "head_bucket"): "Bucket",
                        ("s3", "get_bucket_tagging"): "Bucket",
                        ("s3", "get_bucket_location"): "Bucket",
                        ("s3", "get_public_access_block"): "Bucket",
                        ("s3", "get_bucket_encryption"): "Bucket",
                        ("s3", "get_bucket_versioning"): "Bucket",
                        ("s3", "get_bucket_policy_status"): "Bucket",
                        ("s3", "get_bucket_policy"): "Bucket",
                        ("s3", "get_bucket_ownership_controls"): "Bucket",
                        ("s3", "get_bucket_lifecycle_configuration"): "Bucket",
                        ("kms", "get_key_rotation_status"): "KeyId",
                        ("kms", "get_key_policy"): "KeyId",
                        ("kms", "list_resource_tags"): "KeyId",
                        ("logs", "list_tags_for_resource"): "resourceArn",
                        ("iam", "list_role_tags"): "RoleName",
                        ("ecr", "list_tags_for_resource"): "resourceArn",
                        ("dynamodb", "list_tags_of_resource"): "ResourceArn",
                        ("dynamodb", "describe_continuous_backups"): "TableName",
                        ("ecr", "get_lifecycle_policy"): "repositoryName",
                        ("opensearch", "list_tags"): "ARN",
                    }
                    argument_name = scope_arguments.get((spec.service, spec.method))
                    if (
                        argument_name is None
                        or arguments.get(argument_name) != spec.expected_native_identity
                    ):
                        raise ContractError("NATIVE_IMPLICIT_IDENTITY_NOT_BOUND")
                    identity = spec.expected_native_identity
                if not isinstance(identity, str) or identity in seen:
                    raise ContractError("NATIVE_IDENTITY_MALFORMED_OR_DUPLICATED")
                seen.add(identity)
                if identity == spec.expected_native_identity:
                    matched += 1
                    if (spec.service, spec.method) == ("kms", "describe_key"):
                        key_state = item.get("KeyState")
                        if not isinstance(key_state, str):
                            raise ContractError("KMS_STATE_UNCLASSIFIED")
                        if key_state == "PendingDeletion":
                            deletion = item.get("DeletionDate")
                            if not isinstance(
                                deletion, datetime
                            ) or deletion.utcoffset() != timedelta(0):
                                raise ContractError("KMS_DELETION_DATE_UNCLASSIFIED")
                            scheduled_deletion_at = (
                                deletion.replace(microsecond=0).isoformat().replace("+00:00", "Z")
                            )
                    if (spec.service, spec.method) == ("s3", "head_object"):
                        version = item.get("VersionId")
                        if not isinstance(version, str) or not version or version == "null":
                            raise ContractError("REMOTE_STATE_VERSION_REQUIRED")
                        remote_version = version
                    if expected_fields:
                        comparison_item = item
                        if self._diagnostic_details and (spec.service, spec.method) == (
                            "s3",
                            "get_bucket_lifecycle_configuration",
                        ):
                            comparison_item = _diagnostic_lifecycle_comparison_item(
                                spec, item, expected_fields
                            )
                            mismatches = _lifecycle_mismatch_paths(
                                comparison_item.get("Rules"),
                                expected_fields.get("Rules.@unordered"),
                            )
                            comparison_notes = _lifecycle_prefix_notes(item)
                        if self._diagnostic_details and (
                            spec.resource_type == "aws_vpc_endpoint"
                            and (spec.service, spec.method) == ("ec2", "describe_vpc_endpoints")
                        ):
                            comparison_item = _diagnostic_endpoint_comparison_item(
                                item, expected_fields
                            )
                            mismatches, comparison_notes = _endpoint_comparison_details(
                                comparison_item, expected_fields
                            )
                        try:
                            configuration = (
                                Outcome.PASS
                                if all(
                                    canonical_json_bytes(_native_field(comparison_item, path))
                                    == canonical_json_bytes(expected)
                                    and type(_native_field(comparison_item, path)) is type(expected)
                                    for path, expected in expected_fields.items()
                                )
                                else Outcome.FAIL
                            )
                        except ContractError:
                            if not mismatches:
                                raise
                            # Path diagnostics cannot turn missing/malformed fields into PASS.
                            configuration = Outcome.FAIL
            next_token = response.get(spec.response_token) if spec.response_token else None
            # A partial page must never become absence because a caller omitted or
            # misspelled the continuation contract. Compound S3 pagination requires
            # its dedicated inventory adapter, not this single-token reader.
            continuation_fields = {
                "NextToken",
                "nextToken",
                "Marker",
                "NextMarker",
                "PaginationToken",
                "NextKeyMarker",
                "NextVersionIdMarker",
                "NextUploadIdMarker",
            }
            unexpected_continuation = any(
                response.get(key) not in (None, "")
                for key in continuation_fields - {spec.response_token}
            )
            truncated = response.get("IsTruncated", False)
            if type(truncated) is not bool:
                raise ContractError("NATIVE_TRUNCATION_MALFORMED")
            if unexpected_continuation or (truncated and next_token in (None, "")):
                return NativeProbeResult(
                    spec.address,
                    spec.resource_type,
                    "INDETERMINATE",
                    "NATIVE_PAGINATION_INCOMPLETE",
                    page,
                    matched,
                )
            if next_token in (None, ""):
                return NativeProbeResult(
                    spec.address,
                    spec.resource_type,
                    "PRESENT" if matched == 1 else "ABSENT",
                    "NATIVE_READ_COMPLETE",
                    page,
                    matched,
                    configuration,
                    remote_version,
                    key_state,
                    scheduled_deletion_at,
                    mismatches,
                    comparison_notes,
                )
            if (
                not isinstance(next_token, str)
                or next_token in tokens
                or spec.request_token is None
            ):
                raise ContractError("NATIVE_PAGINATION_INVALID")
            tokens.add(next_token)
            arguments[spec.request_token] = next_token
        return NativeProbeResult(
            spec.address,
            spec.resource_type,
            "INDETERMINATE",
            "NATIVE_PAGE_LIMIT",
            spec.maximum_pages,
            matched,
        )


def _native_field(value: object, path: str) -> object:
    """Resolve only literal object keys and numeric array indices, not expressions."""
    if not path or any(part in {"", ".."} for part in path.split(".")):
        raise ContractError("NATIVE_ASSERTION_PATH_INVALID")
    for part in path.split("."):
        if part == "@kms_identity":
            if not isinstance(value, str):
                raise ContractError("NATIVE_KMS_IDENTITY_REQUIRED")
            value = native_identity_key("kms", value)[1]
            continue
        if part == "@unordered":
            value = native_unordered_value(value)
            continue
        if part == "@json":
            if not isinstance(value, str):
                raise ContractError("NATIVE_JSON_STRING_REQUIRED")
            value = decode_json_strict(value.encode("utf-8"))
            continue
        if part == "@policy_sha256":
            value = native_policy_digest(value)
            continue
        if part == "@diagnostic_policy_sha256":
            value = diagnostic_policy_digest(value)
            continue
        if isinstance(value, dict) and part in value:
            value = value[part]
        elif isinstance(value, list) and part.isdecimal() and int(part) < len(value):
            value = value[int(part)]
        else:
            raise ContractError("NATIVE_ASSERTION_FIELD_UNAVAILABLE")
    if path.split(".")[-1] in {"Tags", "TagSet", "TagList", "tags"} and isinstance(value, list):
        tags: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict) or set(item) not in (
                {"Key", "Value"},
                {"TagKey", "TagValue"},
                {"key", "value"},
            ):
                raise ContractError("NATIVE_TAG_STRUCTURE_INVALID")
            key, content = (
                (item["Key"], item["Value"])
                if "Key" in item
                else (item["TagKey"], item["TagValue"])
                if "TagKey" in item
                else (item["key"], item["value"])
            )
            if not isinstance(key, str) or not isinstance(content, str) or key in tags:
                raise ContractError("NATIVE_TAG_STRUCTURE_INVALID")
            tags[key] = content
        return tags
    return value


def native_unordered_value(value: object) -> object:
    """Canonicalize array ordering without dropping duplicate or unexpected members."""
    if isinstance(value, list):
        return sorted((native_unordered_value(item) for item in value), key=canonical_json_bytes)
    if isinstance(value, dict):
        return {key: native_unordered_value(item) for key, item in value.items()}
    return value


def native_policy_digest(value: object) -> str:
    """Preserve the established operational policy fingerprint contract."""
    from .lifecycle_io import sha256_bytes
    from .policy_runner import policy_semantic_value

    if not isinstance(value, (dict, str)):
        raise ContractError("NATIVE_POLICY_STRUCTURE_INVALID")
    raw = value if isinstance(value, str) else canonical_json_bytes(value).decode()
    return sha256_bytes(canonical_json_bytes(policy_semantic_value(raw)))


def diagnostic_policy_digest(value: object) -> str:
    """Compare native IAM semantics without discarding fields or duplicate members."""
    from .lifecycle_io import sha256_bytes
    from .policy_runner import policy_semantic_value

    if not isinstance(value, (dict, str)):
        raise ContractError("NATIVE_POLICY_STRUCTURE_INVALID")
    raw = value if isinstance(value, str) else canonical_json_bytes(value).decode()
    policy = policy_semantic_value(raw)
    if not isinstance(policy, dict):
        raise ContractError("NATIVE_POLICY_STRUCTURE_INVALID")
    statements = policy.get("Statement")
    if not isinstance(statements, list):
        raise ContractError("NATIVE_POLICY_STATEMENTS_REQUIRED")
    for statement in statements:
        if not isinstance(statement, dict):
            raise ContractError("NATIVE_POLICY_STATEMENT_REQUIRED")
        for field in ("Principal", "NotPrincipal"):
            principal = statement.get(field)
            if isinstance(principal, dict):
                for kind, identities in principal.items():
                    if isinstance(identities, str):
                        principal[kind] = [identities]
        condition = statement.get("Condition")
        if isinstance(condition, dict):
            for clauses in condition.values():
                if isinstance(clauses, dict):
                    for key, operand in clauses.items():
                        if isinstance(operand, str):
                            clauses[key] = [operand]
    return sha256_bytes(canonical_json_bytes(native_unordered_value(policy)))


def _validate_native_scope(service: str, value: object) -> None:
    if isinstance(value, str) and value.startswith("arn:"):
        parts = value.split(":", 5)
        if len(parts) != 6 or parts[0:2] != ["arn", "aws"]:
            raise ContractError("NATIVE_ARN_PARTITION_INVALID")
        if parts[2] == "s3":
            if parts[3] or parts[4]:
                raise ContractError("NATIVE_S3_ARN_SCOPE_INVALID")
        elif parts[4] != APPROVED_AWS_ACCOUNT_ID or (
            parts[3] != ("" if parts[2] == "iam" else APPROVED_AWS_REGION)
        ):
            raise ContractError("NATIVE_ARN_SCOPE_MISMATCH")
    elif isinstance(value, dict):
        if (
            service == "s3"
            and "Bucket" in value
            and (value.get("ExpectedBucketOwner") != APPROVED_AWS_ACCOUNT_ID)
        ):
            raise ContractError("NATIVE_BUCKET_OWNER_REQUIRED")
        for child in value.values():
            _validate_native_scope(service, child)
    elif isinstance(value, list):
        for child in value:
            _validate_native_scope(service, child)


_REQUIRED_CONFIGURATION_FIELDS: Mapping[str, Mapping[str, frozenset[str]]] = {
    "aws_vpc": {"describe_vpcs": frozenset({"CidrBlock", "State"})},
    "aws_subnet": {"describe_subnets": frozenset({"VpcId", "CidrBlock", "MapPublicIpOnLaunch"})},
    "aws_route_table": {"describe_route_tables": frozenset({"VpcId", "Routes"})},
    "aws_route_table_association": {"describe_route_tables": frozenset({"Associations"})},
    "aws_security_group": {
        "describe_security_groups": frozenset({"VpcId", "IpPermissions", "IpPermissionsEgress"})
    },
    "aws_default_security_group": {
        "describe_security_groups": frozenset({"VpcId", "IpPermissions", "IpPermissionsEgress"})
    },
    "aws_vpc_endpoint": {
        "describe_vpc_endpoints": frozenset(
            {"VpcId", "VpcEndpointType", "ServiceName", "State", "PolicyDocument"}
        )
    },
    "aws_kms_key": {
        "describe_key": frozenset({"KeyState", "KeyManager"}),
        "get_key_rotation_status": frozenset({"KeyRotationEnabled"}),
        "get_key_policy": frozenset({"@policy_sha256"}),
    },
    "aws_kms_alias": {"list_aliases": frozenset({"AliasName", "TargetKeyId"})},
    "aws_s3_bucket": {"get_bucket_location": frozenset({"LocationConstraint"})},
    "aws_s3_bucket_ownership_controls": {
        "get_bucket_ownership_controls": frozenset({"ObjectOwnership"})
    },
    "aws_s3_bucket_public_access_block": {
        "get_public_access_block": frozenset(
            {
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            }
        )
    },
    "aws_s3_bucket_versioning": {"get_bucket_versioning": frozenset({"Status"})},
    "aws_s3_bucket_server_side_encryption_configuration": {
        "get_bucket_encryption": frozenset({"SSEAlgorithm", "KMSMasterKeyID"})
    },
    "aws_s3_bucket_lifecycle_configuration": {
        "get_bucket_lifecycle_configuration": frozenset({"Rules"})
    },
    "aws_s3_bucket_policy": {"get_bucket_policy": frozenset({"@policy_sha256"})},
    "aws_dynamodb_table": {
        "describe_table": frozenset({"TableStatus", "BillingMode", "SSEType", "KMSMasterKeyArn"}),
        "describe_continuous_backups": frozenset({"PointInTimeRecoveryStatus"}),
    },
    "aws_iam_role": {"get_role": frozenset({"@policy_sha256", "Arn"})},
    "aws_iam_role_policy": {"get_role_policy": frozenset({"RoleName", "@policy_sha256"})},
    "aws_cloudwatch_log_group": {"describe_log_groups": frozenset({"retentionInDays", "kmsKeyId"})},
    "aws_cloudwatch_log_resource_policy": {
        "describe_resource_policies": frozenset({"@policy_sha256"})
    },
    "aws_ecr_repository": {
        "describe_repositories": frozenset(
            {"imageTagMutability", "scanOnPush", "encryptionType", "kmsKey"}
        )
    },
    "aws_ecr_lifecycle_policy": {"get_lifecycle_policy": frozenset({"lifecyclePolicyText"})},
    "aws_opensearch_domain": {
        "describe_domain": frozenset(
            {
                "Created",
                "Deleted",
                "Processing",
                "VPCOptions",
                "EncryptionAtRestOptions",
                "NodeToNodeEncryptionOptions",
                "DomainEndpointOptions",
                "AdvancedSecurityOptions",
                "LogPublishingOptions",
                "AccessPolicies",
                "ClusterConfig",
                "EBSOptions",
            }
        )
    },
    "aws_secretsmanager_secret": {"describe_secret": frozenset({"KmsKeyId", "Name"})},
}


def _require_configuration_coverage(target: NativeTarget, presence: NativeProbeResult) -> None:
    requirements = _REQUIRED_CONFIGURATION_FIELDS.get(target.resource_type)
    if requirements is None:
        raise ContractError("NATIVE_CONFIGURATION_RESOURCE_NOT_SUPPORTED")
    if target.resource_type == "aws_kms_key" and presence.key_state == "PendingDeletion":
        requirements = {"describe_key": frozenset({"KeyState"})}
    supplied: dict[str, set[str]] = {}
    for assertion in target.assertions:
        if assertion.category != "CONFIGURATION":
            continue
        values = decode_json_strict(assertion.expected_fields_json.encode("utf-8"))
        if not isinstance(values, dict):
            raise ContractError("NATIVE_CONFIGURATION_FIELDS_INVALID")
        fields = supplied.setdefault(assertion.probe.method, set())
        for path in values:
            fields.update(path.split("."))
            if path.endswith(".@diagnostic_policy_sha256"):
                fields.add("@policy_sha256")
    if any(
        not fields.issubset(supplied.get(method, set())) for method, fields in requirements.items()
    ):
        raise ContractError("NATIVE_SECURITY_CONFIGURATION_COVERAGE_INCOMPLETE")


def diagnose_native_target(
    session: DiagnosticAwsSession,
    target: NativeTarget,
    *,
    operation_id: str,
    observed_at: str,
    valid_until: str,
) -> tuple[InventoryResult | None, tuple[dict[str, object], ...]]:
    """Aggregate assertions without accepting less than the operational native contract."""

    class Reader(BoundedNativeReader):
        def __init__(self) -> None:
            super().__init__(session.provider, session.client, diagnostic_details=True)
            self.cache: dict[tuple[NativeReadSpec, bytes], NativeProbeResult] = {}

        def inspect(
            self,
            spec: NativeReadSpec,
            *,
            expected_fields: Mapping[str, object] | None = None,
        ) -> NativeProbeResult:
            try:
                _validate_native_scope(spec.service, spec.expected_native_identity)
                _validate_native_scope(
                    spec.service,
                    decode_json_strict(spec.arguments_json.encode()),
                )
            except ContractError:
                session.reject("DIAGNOSTIC_NATIVE_IDENTITY_OR_ROUTING")
            key = spec, canonical_json_bytes(expected_fields)
            if key not in self.cache:
                self.cache[key] = super().inspect(spec, expected_fields=expected_fields)
            return self.cache[key]

    reader = Reader()
    details: list[dict[str, object]] = []
    try:
        presence = reader.inspect(target.presence)
    except DiagnosticFatalError as exc:
        if session.fatal_reason is None:
            session.fatal_reason = diagnostic_failure_reason(exc)
        return None, (
            {
                "check": "PRESENCE",
                "status": "FAIL",
                "service": target.presence.service,
                "method": target.presence.method,
                "reason_code": diagnostic_failure_reason(exc),
            },
        )
    details.append(
        {
            "check": "PRESENCE",
            "status": presence.presence,
            "service": target.presence.service,
            "method": target.presence.method,
            "reason_code": presence.reason_code,
        }
    )
    owned = presence.presence == "PRESENT"
    complete = presence.presence in {"PRESENT", "ABSENT"}
    structural = any(item.category == "SOURCE_OWNERSHIP" for item in target.assertions)
    if structural and (
        target.address != "module.opensearch.aws_cloudwatch_log_resource_policy.opensearch"
        or target.resource_type != "aws_cloudwatch_log_resource_policy"
        or target.presence.service != "logs"
        or target.presence.method != "describe_resource_policies"
        or target.presence.expected_native_identity
        != "enterprise-ai-sandbox-opensearch-log-delivery"
    ):
        raise ContractError("DIAGNOSTIC_STRUCTURAL_OWNERSHIP_SCOPE")
    for category in (
        ("SOURCE_OWNERSHIP", "CONFIGURATION") if structural else ("OWNERSHIP", "CONFIGURATION")
    ):
        for index, assertion in enumerate(target.assertions):
            if assertion.category != category:
                continue
            if not owned or session.fatal_reason is not None:
                details.append(
                    {
                        "check": category,
                        "index": index,
                        "status": (
                            "NOT_APPLICABLE_ABSENT"
                            if presence.presence == "ABSENT"
                            else "BLOCKED_DEPENDENCY"
                        ),
                    }
                )
                continue
            reason = "NATIVE_ASSERTION_UNRESOLVED"
            mismatches: tuple[tuple[str, str], ...] = ()
            comparison_notes: tuple[tuple[str, str], ...] = ()
            try:
                fields = decode_json_strict(assertion.expected_fields_json.encode())
                if not isinstance(fields, dict) or not fields:
                    raise ContractError("DIAGNOSTIC_ASSERTION_FIELDS_REQUIRED")
                result = reader.inspect(assertion.probe, expected_fields=fields)
                reason = (
                    "NATIVE_CONFIGURATION_MISMATCH"
                    if result.configuration is Outcome.FAIL
                    else result.reason_code
                )
                mismatches = result.mismatches
                comparison_notes = result.comparison_notes
                passed = result.presence == "PRESENT" and result.configuration is Outcome.PASS
                status = (
                    "PASS"
                    if passed
                    else ("FAIL" if result.configuration is Outcome.FAIL else "INDETERMINATE")
                )
            except DiagnosticFatalError as exc:
                passed = False
                status = "FAIL"
                reason = diagnostic_failure_reason(exc)
                if session.fatal_reason is None:
                    session.fatal_reason = reason
            except Exception as exc:
                passed = False
                status = "INDETERMINATE"
                reason = diagnostic_failure_reason(exc)
            details.append(
                {
                    "check": category,
                    "index": index,
                    "status": status,
                    "service": assertion.probe.service,
                    "method": assertion.probe.method,
                    "reason_code": reason,
                    "mismatches": [
                        {"path": path, "classification": classification}
                        for path, classification in mismatches
                    ],
                    "comparison_notes": [
                        {"path": path, "classification": classification}
                        for path, classification in comparison_notes
                    ],
                }
            )
            complete = complete and passed
        if category in {"OWNERSHIP", "SOURCE_OWNERSHIP"} and not complete:
            owned = False
    if not complete:
        return None, tuple(details)
    if structural:
        # This proof is diagnostic-only. The shared operational ownership gate above
        # still rejects SOURCE_OWNERSHIP; this record cannot authorize a mutation.
        from .aws_inventory import diagnostic_policy_templates

        policy = diagnostic_policy_templates("platform")["log_delivery"]
        digest = diagnostic_policy_digest(policy)
        owners = [item for item in target.assertions if item.category == "SOURCE_OWNERSHIP"]
        if len(owners) != 1 or decode_json_strict(owners[0].expected_fields_json.encode()) != {
            "policyName": "enterprise-ai-sandbox-opensearch-log-delivery",
            "policyDocument.@diagnostic_policy_sha256": digest,
        }:
            raise ContractError("DIAGNOSTIC_STRUCTURAL_OWNERSHIP_NOT_EXACT")
        _require_configuration_coverage(target, presence)
        entry = InventoryEntry(
            target.address,
            target.resource_type,
            target.presence.expected_native_identity if presence.presence == "PRESENT" else None,
            None,
            "SOURCE_BOUND_DIAGNOSTIC_ONLY",
            presence.presence,
            Outcome.PASS if presence.presence == "PRESENT" else Outcome.NOT_RUN,
            False,
            observed_at,
            None,
        )
        return InventoryResult(
            OPERATIONAL_SCHEMA_VERSION,
            operation_id,
            APPROVED_AWS_ACCOUNT_ID,
            APPROVED_AWS_REGION,
            (entry,),
            ("logs",),
            (),
            observed_at,
            valid_until,
        ), tuple(details)
    try:
        inventory = observe_native_targets(
            session.provider,
            reader,
            (target,),
            operation_id=operation_id,
            observed_at=observed_at,
            valid_until=valid_until,
        )
    except DiagnosticFatalError:
        raise
    except ContractError:
        details.append({"check": "FULL_SECURITY_CONTRACT", "status": "INDETERMINATE"})
        return None, tuple(details)
    return inventory, tuple(details)


def observe_native_targets(
    provider: Boto3AwsInventoryProvider,
    reader: BoundedNativeReader,
    targets: tuple[NativeTarget, ...],
    *,
    operation_id: str,
    observed_at: str,
    valid_until: str,
) -> InventoryResult:
    """Execute bound native assertions; lack of a configuration proof stays indeterminate."""
    identity = provider.verify_identity()
    if not targets or len({target.address for target in targets}) != len(targets):
        raise ContractError("NATIVE_TARGET_INVENTORY_INVALID")
    entries: list[InventoryEntry] = []
    covered: set[str] = set()
    incomplete: set[str] = set()
    for target in targets:
        probe = target.presence
        if (target.address, target.resource_type) != (probe.address, probe.resource_type):
            raise ContractError("NATIVE_TARGET_PROBE_MISMATCH")
        presence = reader.inspect(probe)
        configuration = Outcome.NOT_RUN
        ownership = "INDETERMINATE"
        if presence.presence == "PRESENT":
            _require_configuration_coverage(target, presence)
            categories = {assertion.category for assertion in target.assertions}
            if categories != {"OWNERSHIP", "CONFIGURATION"}:
                raise ContractError("NATIVE_OWNERSHIP_AND_CONFIGURATION_REQUIRED")
            for assertion in target.assertions:
                check = assertion.probe
                if (check.address, check.resource_type) != (target.address, target.resource_type):
                    raise ContractError("NATIVE_ASSERTION_RESOURCE_MISMATCH")
                fields = decode_json_strict(assertion.expected_fields_json.encode("utf-8"))
                if not isinstance(fields, dict) or not fields:
                    raise ContractError("NATIVE_ASSERTION_EXPECTATIONS_REQUIRED")
                if assertion.category == "OWNERSHIP":
                    if check.expected_native_identity != probe.expected_native_identity:
                        binding = target.ownership_binding
                        if (
                            binding is None
                            or binding.parent_identity != check.expected_native_identity
                        ):
                            raise ContractError("NATIVE_PARENT_OWNERSHIP_NOT_BOUND")
                        linked = reader.inspect(
                            probe,
                            expected_fields={
                                binding.consumer_field: binding.parent_identity,
                            },
                        )
                        if linked.presence != "PRESENT" or linked.configuration is not Outcome.PASS:
                            raise ContractError("NATIVE_PARENT_RELATIONSHIP_UNPROVEN")
                    if len(fields) != 1:
                        raise ContractError("NATIVE_TAG_OWNERSHIP_REQUIRED")
                    path, expected_tags = next(iter(fields.items()))
                    if path.split(".")[-1] not in {
                        "Tags",
                        "TagSet",
                        "TagList",
                        "tags",
                    } or not isinstance(expected_tags, dict):
                        raise ContractError("NATIVE_TAG_OWNERSHIP_REQUIRED")
                    if any(
                        expected_tags.get(key) != value
                        for key, value in stable_cleanup_tags("sandbox").items()
                    ):
                        raise ContractError("NATIVE_PROJECT_TAGS_NOT_APPROVED")
                    parse_utc_timestamp(
                        str(expected_tags.get("ExpiresAt", "")), "native tag expiry"
                    )
                checked = reader.inspect(check, expected_fields=fields)
                if checked.presence != "PRESENT" or checked.configuration is not Outcome.PASS:
                    raise ContractError("NATIVE_OWNERSHIP_OR_CONFIGURATION_FAILED")
            ownership = "PROJECT_MANAGED"
            configuration = Outcome.PASS
        elif presence.presence == "ABSENT":
            ownership = "PROJECT_MANAGED"
        else:
            incomplete.add(probe.service)
        covered.add(probe.service)
        entries.append(
            InventoryEntry(
                target.address,
                target.resource_type,
                probe.expected_native_identity if presence.presence == "PRESENT" else None,
                None,
                ownership,
                "PENDING_DELETION"
                if presence.key_state == "PendingDeletion"
                else presence.presence,
                configuration,
                target.cost_bearing if presence.presence != "ABSENT" else False,
                observed_at,
                presence.scheduled_deletion_at,
            )
        )
    return InventoryResult(
        OPERATIONAL_SCHEMA_VERSION,
        operation_id,
        identity.account_id,
        identity.region,
        tuple(sorted(entries, key=lambda entry: entry.address)),
        tuple(sorted(covered)),
        tuple(sorted(incomplete)),
        observed_at,
        valid_until,
    )


class S3PurgeAdapter:
    """Account-bound exact version/upload removal, with no SDK mutation retries."""

    def __init__(
        self,
        provider: Boto3AwsInventoryProvider,
        client_factory: Callable[[str, str], object],
    ) -> None:
        self._provider = provider
        self._client_factory = client_factory

    def _call(
        self,
        method: str,
        arguments: dict[str, object],
        *,
        context: VerifiedExecutionContext | None = None,
        ledger: OperationLedger | None = None,
        sequence: int | None = None,
    ) -> dict[str, object]:
        if method in {"delete_object", "abort_multipart_upload"}:
            if (
                not isinstance(context, VerifiedExecutionContext)
                or not isinstance(ledger, OperationLedger)
                or type(sequence) is not int
            ):
                raise ContractError("PURGE_LOW_LEVEL_AUTHORITY_REQUIRED")
            if context.package.action is not Action.PURGE_SANDBOX:
                raise ContractError("PURGE_ACTION_REQUIRED")
            inventory = decode_operational_record(context.artifact_bytes(), PurgeInventoryV2)
            if not 1 <= sequence <= len(inventory.items):
                raise ContractError("PURGE_SEQUENCE_INVALID")
            item = inventory.items[sequence - 1]
            multipart = item.kind == "MULTIPART_UPLOAD"
            expected_method = "abort_multipart_upload" if multipart else "delete_object"
            expected_arguments = {
                "Bucket": inventory.bucket,
                "Key": item.key,
                "ExpectedBucketOwner": APPROVED_AWS_ACCOUNT_ID,
                "UploadId" if multipart else "VersionId": item.identifier,
            }
            if method != expected_method or arguments != expected_arguments:
                raise ContractError("PURGE_LOW_LEVEL_TARGET_MISMATCH")
            context.revalidate(Action.PURGE_SANDBOX, context.package.artifact.sha256, consumed=True)
            ledger.require_purge_batch(context, sequence, item)
            if sequence == 1:
                context.claim_dispatch(Action.PURGE_SANDBOX, context.package.artifact.sha256)
            elif not context.dispatch_started:
                raise ContractError("PURGE_PRIOR_DISPATCH_REQUIRED")
        elif method not in {
            "get_bucket_location",
            "get_bucket_tagging",
            "list_object_versions",
            "list_multipart_uploads",
        }:
            raise ContractError("PURGE_S3_METHOD_NOT_APPROVED")
        self._provider.verify_identity()
        client = self._client_factory("s3", APPROVED_AWS_REGION)
        function = getattr(client, method, None)
        if not callable(function):
            raise ContractError("PURGE_S3_ADAPTER_UNAVAILABLE")
        try:
            value = function(**arguments)
        except Exception as exc:
            raise ContractError("PURGE_S3_OUTCOME_UNPROVEN") from exc
        if not isinstance(value, dict):
            raise ContractError("PURGE_S3_RESPONSE_MALFORMED")
        return cast(dict[str, object], value)

    def inventory(self, expected: PurgeInventoryV2) -> tuple[PurgeItem, ...]:
        if expected.account_id != APPROVED_AWS_ACCOUNT_ID or expected.region != APPROVED_AWS_REGION:
            raise ContractError("PURGE_IDENTITY_MISMATCH")
        arguments: dict[str, object] = {
            "Bucket": expected.bucket,
            "ExpectedBucketOwner": APPROVED_AWS_ACCOUNT_ID,
        }
        location = self._call("get_bucket_location", arguments)
        if location.get("LocationConstraint") != APPROVED_AWS_REGION:
            raise ContractError("PURGE_BUCKET_REGION_MISMATCH")
        tagging = self._call("get_bucket_tagging", arguments).get("TagSet")
        if not isinstance(tagging, list):
            raise ContractError("PURGE_BUCKET_OWNERSHIP_UNPROVEN")
        tags: dict[str, str] = {}
        for item in tagging:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("Key"), str)
                or not isinstance(item.get("Value"), str)
            ):
                raise ContractError("PURGE_BUCKET_TAGS_MALFORMED")
            if item["Key"] in tags:
                raise ContractError("PURGE_BUCKET_TAGS_DUPLICATED")
            tags[item["Key"]] = item["Value"]
        if any(
            tags.get(key) != value
            for key, value in stable_cleanup_tags(expected.environment).items()
        ):
            raise ContractError("PURGE_BUCKET_OWNERSHIP_UNPROVEN")
        parse_utc_timestamp(tags.get("ExpiresAt", ""), "purge ownership expiry")
        items: list[PurgeItem] = []
        for method, groups, marker_names in (
            (
                "list_object_versions",
                (
                    ("Versions", "OBJECT_VERSION", "VersionId"),
                    ("DeleteMarkers", "DELETE_MARKER", "VersionId"),
                ),
                (("NextKeyMarker", "KeyMarker"), ("NextVersionIdMarker", "VersionIdMarker")),
            ),
            (
                "list_multipart_uploads",
                (("Uploads", "MULTIPART_UPLOAD", "UploadId"),),
                (("NextKeyMarker", "KeyMarker"), ("NextUploadIdMarker", "UploadIdMarker")),
            ),
        ):
            query = dict(arguments)
            query["MaxKeys" if method == "list_object_versions" else "MaxUploads"] = 1000
            seen_markers: set[tuple[str, ...]] = set()
            for _ in range(100):
                response = self._call(method, query)
                for field, kind, identity_field in groups:
                    values = response.get(field, [])
                    if not isinstance(values, list):
                        raise ContractError("PURGE_INVENTORY_MALFORMED")
                    for value in values:
                        if (
                            not isinstance(value, dict)
                            or not isinstance(value.get("Key"), str)
                            or not isinstance(value.get(identity_field), str)
                        ):
                            raise ContractError("PURGE_ITEM_MALFORMED")
                        items.append(PurgeItem(kind, value["Key"], value[identity_field]))
                        if len(items) > 10000:
                            raise ContractError("PURGE_INVENTORY_LIMIT")
                truncated = response.get("IsTruncated")
                if type(truncated) is not bool:
                    raise ContractError("PURGE_PAGINATION_MALFORMED")
                if not truncated:
                    break
                markers = tuple(response.get(source) for source, _ in marker_names)
                if any(not isinstance(value, str) or not value for value in markers):
                    raise ContractError("PURGE_PAGINATION_INCOMPLETE")
                marker_tuple = cast(tuple[str, ...], markers)
                if marker_tuple in seen_markers:
                    raise ContractError("PURGE_PAGINATION_CYCLE")
                seen_markers.add(marker_tuple)
                for (_, destination), value in zip(marker_names, marker_tuple, strict=True):
                    query[destination] = value
            else:
                raise ContractError("PURGE_PAGE_LIMIT")
        if len(items) != len(set(items)):
            raise ContractError("PURGE_INVENTORY_DUPLICATED")
        return tuple(sorted(items, key=lambda item: (item.kind, item.key, item.identifier)))

    def remove(
        self,
        item: PurgeItem,
        *,
        context: VerifiedExecutionContext,
        ledger: OperationLedger,
        sequence: int,
    ) -> None:
        if (
            not isinstance(context, VerifiedExecutionContext)
            or context.package.action is not Action.PURGE_SANDBOX
        ):
            raise ContractError("PURGE_VERIFIED_CONTEXT_REQUIRED")
        inventory = decode_operational_record(context.artifact_bytes(), PurgeInventoryV2)
        if not 1 <= sequence <= len(inventory.items) or inventory.items[sequence - 1] != item:
            raise ContractError("PURGE_EXACT_ITEM_REQUIRED")
        context.revalidate(Action.PURGE_SANDBOX, context.package.artifact.sha256, consumed=True)
        self._provider.verify_identity()
        arguments: dict[str, object] = {
            "Bucket": inventory.bucket,
            "Key": item.key,
            "ExpectedBucketOwner": APPROVED_AWS_ACCOUNT_ID,
        }
        if item.kind == "MULTIPART_UPLOAD":
            arguments["UploadId"] = item.identifier
            self._call(
                "abort_multipart_upload",
                arguments,
                context=context,
                ledger=ledger,
                sequence=sequence,
            )
        elif item.kind in {"OBJECT_VERSION", "DELETE_MARKER"}:
            arguments["VersionId"] = item.identifier
            self._call(
                "delete_object", arguments, context=context, ledger=ledger, sequence=sequence
            )
        else:
            raise ContractError("PURGE_ITEM_KIND_INVALID")
