"""Strict offline contracts for owner-gated platform lifecycle actions."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from .lifecycle_models import (
        ApprovalRecordV2,
        DispatchObservation,
        IdentityBundle,
        NativePrerequisiteEvidence,
        RecoveryProfile,
        ReviewPackage,
        StateEvidence,
        TemporaryIamOperation,
    )

APPROVAL_SCHEMA_VERSION = "1.0"
APPROVER = "Gyan-Prakash-Rai"
EXECUTOR = "Gyan-Prakash-Rai"
MAX_APPROVAL_LIFETIME = timedelta(minutes=60)
MAX_SANDBOX_RESOURCE_LIFETIME = timedelta(hours=24)
GENERATED_RESOURCE_LIFETIME = timedelta(hours=23, minutes=45)
OWNER_GOVERNANCE_EXPIRES_AT = "2026-12-09T23:59:59Z"
APPROVED_AWS_ACCOUNT_ID = "526338061652"
APPROVED_AWS_REGION = "ap-southeast-1"
APPROVED_ENVIRONMENT = "sandbox"
APPROVED_CALLER_ARN = "arn:aws:iam::526338061652:user/finopsinfra"

REQUIRED_APPROVAL_FIELDS = frozenset(
    {
        "schema_version",
        "approval_id",
        "action",
        "environment",
        "aws_account_id",
        "aws_region",
        "target",
        "artifact_sha256",
        "approver",
        "approved_at",
        "expires_at",
    }
)

FIXED_TAG_VALUES: Mapping[str, str] = {
    "Project": "enterprise-ai-platform",
    "Owner": "Gyan-Prakash-Rai",
    "ManagedBy": "terraform",
    "CostCenter": "Personal-Learning",
    "Feature": "MVP-001",
    "Repository": "enterprise-ai-platform",
}

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_ACCOUNT_ID_PATTERN = re.compile(r"^[0-9]{12}$")
_REGION_PATTERN = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")
_PLACEHOLDERS = frozenset({"TODO", "TODO_USER", "CHANGEME", "PLACEHOLDER"})


class ExitCode(IntEnum):
    """Approved W1-004 process result codes."""

    SUCCESS = 0
    VALIDATION_FAILURE = 1
    USAGE_ERROR = 2
    PROVIDER_UNAVAILABLE = 3
    APPROVAL_FAILURE = 4


class Action(StrEnum):
    """Actions that require distinct owner approval."""

    BOOTSTRAP_APPLY = "BOOTSTRAP-APPLY"
    PLATFORM_APPLY = "PLATFORM-APPLY"
    INFRASTRUCTURE_ROLLBACK = "INFRASTRUCTURE-ROLLBACK"
    PURGE_SANDBOX = "PURGE-SANDBOX"
    PLATFORM_DESTROY = "PLATFORM-DESTROY"
    BOOTSTRAP_DESTROY = "BOOTSTRAP-DESTROY"


class ContractError(ValueError):
    """Raised when an offline lifecycle contract is invalid."""


class ApprovalError(ContractError):
    """Raised when owner approval cannot authorize the requested action."""


class ApprovalStateUnavailable(ApprovalError):
    """Raised when one-time approval use cannot be verified."""


class Clock(Protocol):
    """Injectable UTC clock for deterministic validation."""

    def now(self) -> datetime:
        """Return the current UTC time."""
        ...


class SystemClock:
    """Production clock used only for local contract validation."""

    def now(self) -> datetime:
        """Return the current UTC time."""
        return datetime.now(UTC)


class ApprovalUsageRegistry(Protocol):
    """Read-only boundary for detecting already-consumed approvals."""

    def is_used(self, approval_id: str) -> bool:
        """Return whether the approval has already authorized an action."""
        ...


class ApprovalConsumptionRegistry(ApprovalUsageRegistry, Protocol):
    """Durable registry capable of atomically consuming an approval."""

    def consume(self, approval_id: str, artifact_sha256: str, consumed_at: str) -> None:
        """Record one-time use before the approved mutation starts."""
        ...


class UnavailableApprovalUsageRegistry:
    """Fail-closed default until a durable approved ledger exists."""

    def is_used(self, approval_id: str) -> bool:
        """Refuse to claim that one-time approval state is available."""
        del approval_id
        raise ApprovalStateUnavailable("approval reuse state is unavailable")


@dataclass(frozen=True)
class OperationResult:
    """Sanitized result returned by an offline lifecycle command."""

    exit_code: ExitCode
    message: str
    reason_code: str = "INTENT_ONLY"


def parse_utc_timestamp(value: str, field_name: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp that uses the required Z suffix."""
    if (
        not isinstance(value, str)
        or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is None
    ):
        raise ContractError(f"{field_name} must be ISO-8601 UTC with a Z suffix")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ContractError(f"{field_name} must be ISO-8601 UTC with a Z suffix") from exc
    if parsed.utcoffset() != timedelta(0):
        raise ContractError(f"{field_name} must be UTC")
    return parsed


def validate_runtime_token(value: str, field_name: str) -> str:
    """Reject blank, placeholder, or whitespace-delimited runtime tokens."""
    if not value or value in _PLACEHOLDERS or any(char.isspace() for char in value):
        raise ContractError(f"{field_name} must be an explicit non-placeholder token")
    return value


def validate_sha256(value: str) -> str:
    """Require the exact approved lowercase SHA-256 representation."""
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise ContractError("artifact_sha256 must be 64 lowercase hexadecimal characters")
    return value


def validate_aws_account_id(value: str) -> str:
    """Require an explicit non-secret twelve-digit AWS account identifier."""
    if _ACCOUNT_ID_PATTERN.fullmatch(value) is None:
        raise ContractError("aws_account_id must be a twelve-digit identifier")
    return value


def validate_aws_region(value: str) -> str:
    """Validate syntax without approving a live AWS region."""
    validate_runtime_token(value, "aws_region")
    if _REGION_PATTERN.fullmatch(value) is None:
        raise ContractError("aws_region has invalid syntax")
    return value


def _required_string(data: Mapping[str, object], field_name: str) -> str:
    value = data[field_name]
    if not isinstance(value, str):
        raise ApprovalError(f"approval field {field_name} must be a string")
    return value


@dataclass(frozen=True)
class ApprovalRecord:
    """Strict authorization metadata supplied and signed outside W1-004."""

    schema_version: str
    approval_id: str
    action: Action
    environment: str
    aws_account_id: str
    aws_region: str
    target: str
    artifact_sha256: str
    approver: str
    approved_at: str
    expires_at: str

    @classmethod
    def from_mapping(cls, value: object) -> ApprovalRecord:
        """Build a record while rejecting missing and unknown fields."""
        if not isinstance(value, dict):
            raise ApprovalError("approval record must be a JSON object")
        if any(not isinstance(key, str) for key in value):
            raise ApprovalError("approval field names must be strings")
        data = cast(dict[str, object], value)
        actual_fields = set(data)
        if actual_fields != REQUIRED_APPROVAL_FIELDS:
            missing = sorted(REQUIRED_APPROVAL_FIELDS - actual_fields)
            unknown = sorted(actual_fields - REQUIRED_APPROVAL_FIELDS)
            details: list[str] = []
            if missing:
                details.append("missing fields: " + ", ".join(missing))
            if unknown:
                details.append("unknown fields: " + ", ".join(unknown))
            raise ApprovalError("approval contract drift: " + "; ".join(details))

        schema_version = _required_string(data, "schema_version")
        if schema_version != APPROVAL_SCHEMA_VERSION:
            raise ApprovalError("approval schema_version must be 1.0")

        action_value = _required_string(data, "action")
        try:
            action = Action(action_value)
        except ValueError as exc:
            raise ApprovalError("approval action is not permitted") from exc

        try:
            approval_id = validate_runtime_token(
                _required_string(data, "approval_id"), "approval_id"
            )
            environment = validate_runtime_token(
                _required_string(data, "environment"), "environment"
            )
            account_id = validate_aws_account_id(_required_string(data, "aws_account_id"))
            region = validate_aws_region(_required_string(data, "aws_region"))
            target = validate_runtime_token(_required_string(data, "target"), "target")
            artifact_sha256 = validate_sha256(_required_string(data, "artifact_sha256"))
            approver = validate_runtime_token(_required_string(data, "approver"), "approver")
            approved_at = _required_string(data, "approved_at")
            expires_at = _required_string(data, "expires_at")
            parse_utc_timestamp(approved_at, "approved_at")
            parse_utc_timestamp(expires_at, "expires_at")
        except ContractError as exc:
            raise ApprovalError(str(exc)) from exc
        if (
            account_id != APPROVED_AWS_ACCOUNT_ID
            or region != APPROVED_AWS_REGION
            or environment != APPROVED_ENVIRONMENT
        ):
            raise ApprovalError("approval AWS account, Region, or environment is not approved")

        return cls(
            schema_version=schema_version,
            approval_id=approval_id,
            action=action,
            environment=environment,
            aws_account_id=account_id,
            aws_region=region,
            target=target,
            artifact_sha256=artifact_sha256,
            approver=approver,
            approved_at=approved_at,
            expires_at=expires_at,
        )

    @property
    def approved_at_datetime(self) -> datetime:
        """Return the validated approval timestamp."""
        return parse_utc_timestamp(self.approved_at, "approved_at")

    @property
    def expires_at_datetime(self) -> datetime:
        """Return the validated approval expiry timestamp."""
        return parse_utc_timestamp(self.expires_at, "expires_at")

    def validate_at(self, now: datetime) -> None:
        """Validate lifetime, chronology, expiry, and approved authority."""
        approved_at = self.approved_at_datetime
        expires_at = self.expires_at_datetime
        if now.utcoffset() != timedelta(0):
            raise ApprovalError("validation clock must use UTC")
        if approved_at > now:
            raise ApprovalError("approval time cannot be in the future")
        if expires_at <= approved_at:
            raise ApprovalError("approval expiry must be later than approval time")
        if expires_at - approved_at > MAX_APPROVAL_LIFETIME:
            raise ApprovalError("approval lifetime exceeds 60 minutes")
        if expires_at <= now:
            raise ApprovalError("approval has expired")
        if self.approver != APPROVER:
            raise ApprovalError("approval approver is not authorized for this sandbox")

    def confirmation_text(self) -> str:
        """Return the exact owner-approved typed confirmation."""
        return (
            f"CONFIRM {self.action.value} {self.environment} {self.target} "
            f"{self.artifact_sha256} {self.approval_id}"
        )


def load_approval_record(path: Path) -> ApprovalRecord:
    """Read authorization metadata without modifying or signing it."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ApprovalError("approval record is unavailable") from exc
    try:
        value = cast(object, json.loads(raw))
    except json.JSONDecodeError as exc:
        raise ApprovalError("approval record is not valid JSON") from exc
    return ApprovalRecord.from_mapping(value)


@dataclass(frozen=True)
class MutationRequest:
    """Explicit owner request compared against one approval record."""

    action: Action
    environment: str
    aws_account_id: str
    aws_region: str
    target: str
    artifact_sha256: str
    confirmation: str
    executor: str


def _utc_second(value: datetime, field_name: str) -> datetime:
    """Normalize one aware UTC timestamp to deterministic whole-second precision."""
    if value.utcoffset() != timedelta(0):
        raise ContractError(f"{field_name} must use UTC")
    return value.replace(microsecond=0)


def generated_resource_expires_at(plan_preparation_time: datetime) -> str:
    """Derive the one approved resource expiry from a captured plan timestamp."""
    prepared_at = _utc_second(plan_preparation_time, "plan preparation time")
    expires_at = prepared_at + GENERATED_RESOURCE_LIFETIME
    governance_deadline = parse_utc_timestamp(
        OWNER_GOVERNANCE_EXPIRES_AT, "owner governance deadline"
    )
    if expires_at >= governance_deadline:
        raise ContractError("generated resource ExpiresAt reaches the governance deadline")
    return expires_at.isoformat().replace("+00:00", "Z")


def validate_resource_expires_at(
    value: str,
    *,
    plan_preparation_time: datetime,
) -> datetime:
    """Require the exact deterministic expiry generated for one plan."""
    prepared_at = _utc_second(plan_preparation_time, "plan preparation time")
    expires_at = parse_utc_timestamp(value, "resource ExpiresAt")
    if expires_at <= prepared_at:
        raise ContractError("resource ExpiresAt must follow plan preparation time")
    if expires_at - prepared_at > MAX_SANDBOX_RESOURCE_LIFETIME:
        raise ContractError("resource ExpiresAt exceeds the 24-hour sandbox lifetime")
    expected = generated_resource_expires_at(prepared_at)
    if value != expected:
        raise ContractError("resource ExpiresAt is not the generated 23-hour-45-minute value")
    return expires_at


def stable_cleanup_tags(environment: str) -> dict[str, str]:
    """Return stable tags used for cleanup discovery before ExpiresAt validation."""
    validated_environment = validate_runtime_token(environment, "environment")
    return {**FIXED_TAG_VALUES, "Environment": validated_environment}


def canonical_resource_tags(environment: str, expires_at: str) -> dict[str, str]:
    """Return all canonical tags after validating timestamp syntax."""
    parse_utc_timestamp(expires_at, "resource ExpiresAt")
    return {
        **stable_cleanup_tags(environment),
        "ExpiresAt": expires_at,
    }


def validate_mutation_request(
    request: MutationRequest,
    approval: ApprovalRecord,
    usage_registry: ApprovalUsageRegistry,
    now: datetime,
) -> None:
    """Apply every fail-closed approval and confirmation gate."""
    approval.validate_at(now)
    validate_runtime_token(request.environment, "environment")
    validate_aws_account_id(request.aws_account_id)
    validate_aws_region(request.aws_region)
    validate_runtime_token(request.target, "target")
    validate_sha256(request.artifact_sha256)
    if request.executor != EXECUTOR:
        raise ApprovalError("executor is not authorized for this learning sandbox")

    comparisons = {
        "action": request.action == approval.action,
        "environment": request.environment == approval.environment,
        "aws_account_id": request.aws_account_id == approval.aws_account_id,
        "aws_region": request.aws_region == approval.aws_region,
        "target": request.target == approval.target,
        "artifact_sha256": request.artifact_sha256 == approval.artifact_sha256,
    }
    for field_name, matches in comparisons.items():
        if not matches:
            raise ApprovalError(f"approval {field_name} does not match the request")

    if request.confirmation != approval.confirmation_text():
        raise ApprovalError("typed confirmation does not exactly match the approval")

    try:
        already_used = usage_registry.is_used(approval.approval_id)
    except ApprovalStateUnavailable:
        raise
    except Exception as exc:
        raise ApprovalStateUnavailable("approval reuse state is unavailable") from exc
    if already_used:
        raise ApprovalError("approval has already been used")


class EvidenceReader(Protocol):
    """Read verified operation-owned evidence; implementations never trust a path alone."""

    def read(self, relative_path: str, expected_sha256: str, byte_count: int) -> bytes:
        """Return bounded bytes only after independent identity verification."""
        ...


class ExecutionRevalidator(Protocol):
    """Current observations and durable state supplied by the shared coordinator."""

    def observe(self, package: ReviewPackage) -> DispatchObservation:
        """Read source, state, native ownership and caller identities without mutation."""
        ...

    def approval_consumed(self, operation_id: str, approval_id: str) -> bool:
        """Check the matching durable started journal and consumed marker."""
        ...


def _fresh(timestamp: str, now: datetime, maximum_seconds: int) -> None:
    observed = parse_utc_timestamp(timestamp, "observation time")
    age = (now - observed).total_seconds()
    if age < 0 or age > maximum_seconds:
        raise ContractError("EVIDENCE_NOT_FRESH")


def validate_review_package(
    package: ReviewPackage,
    *,
    now: datetime,
    reader: EvidenceReader,
) -> None:
    """Validate all mandatory v2 review controls before considering owner approval."""
    from .lifecycle_io import bounded_relative_path, decode_json_strict
    from .lifecycle_models import (
        CONTENT_SCOPE_VERSION,
        OPERATIONAL_SCHEMA_VERSION,
        ChangeProfile,
        Outcome,
        ReviewPackage,
    )

    if (
        not isinstance(package, ReviewPackage)
        or package.schema_version != OPERATIONAL_SCHEMA_VERSION
    ):
        raise ContractError("V2_REVIEW_REQUIRED")
    if (
        package.account_id != APPROVED_AWS_ACCOUNT_ID
        or package.region != APPROVED_AWS_REGION
        or package.environment != APPROVED_ENVIRONMENT
        or package.caller != APPROVED_CALLER_ARN
        or package.eligibility is not Outcome.PASS
        or package.identities.scope_version != CONTENT_SCOPE_VERSION
    ):
        raise ContractError("REVIEW_IDENTITY_OR_ELIGIBILITY")
    validate_runtime_token(package.operation_id, "operation_id")
    if package.target not in {"bootstrap", "platform"}:
        raise ContractError("REVIEW_TARGET")
    expected_target = (
        "bootstrap"
        if package.action in {Action.BOOTSTRAP_APPLY, Action.BOOTSTRAP_DESTROY}
        else "platform"
    )
    if (
        package.action is not Action.PURGE_SANDBOX and package.target != expected_target
    ) or package.profile.action is not package.action:
        raise ContractError("REVIEW_ACTION_TARGET")
    prepared = parse_utc_timestamp(package.prepared_at, "prepared_at")
    expires = parse_utc_timestamp(package.expires_at, "expires_at")
    resource_expiry = parse_utc_timestamp(package.resource_expires_at, "resource_expires_at")
    if package.action in {Action.PLATFORM_APPLY, Action.BOOTSTRAP_APPLY}:
        validate_resource_expires_at(package.resource_expires_at, plan_preparation_time=prepared)
    governance = parse_utc_timestamp(OWNER_GOVERNANCE_EXPIRES_AT, "governance expiry")
    resource_limit = (
        resource_expiry
        if package.action
        in {
            Action.PLATFORM_APPLY,
            Action.BOOTSTRAP_APPLY,
            Action.INFRASTRUCTURE_ROLLBACK,
        }
        else governance
    )
    if (
        prepared > now
        or expires <= now
        or expires
        > min(
            prepared + MAX_APPROVAL_LIFETIME,
            resource_limit,
            governance,
            parse_utc_timestamp(package.profile.expires_at, "profile expiry"),
            parse_utc_timestamp(package.cost.valid_until, "cost expiry"),
            parse_utc_timestamp(package.native.valid_until, "native expiry"),
        )
    ):
        raise ContractError("REVIEW_EXPIRED_OR_OVERLONG")
    for digest in (
        package.identities.working_sha256,
        package.identities.index_sha256,
        package.identities.authorization_sha256,
        package.identities.governance_sha256,
        package.identities.backend_sha256,
        package.state.sha256,
    ):
        validate_sha256(digest)
    if re.fullmatch(r"[0-9a-f]{40}", package.identities.repository_head) is None:
        raise ContractError("REVIEW_HEAD")
    if not package.identities.tools or not package.identities.inputs:
        raise ContractError("REVIEW_TOOL_OR_INPUT_MISSING")
    tools = {
        name: (path, version, digest) for name, path, version, digest in package.identities.tools
    }
    if len(tools) != len(package.identities.tools) or set(tools) != {
        "git",
        "terraform",
        "opa",
        "infracost",
    }:
        raise ContractError("REVIEW_TOOL_INVENTORY_NOT_EXACT")
    if any(
        tools[name][1] != version
        for name, version in (
            ("terraform", "1.16.1"),
            ("opa", "1.20.0"),
            ("infracost", "0.10.45"),
        )
    ):
        raise ContractError("REVIEW_TOOL_VERSION_NOT_APPROVED")
    for name, path, version, digest in package.identities.tools:
        if not name or not path or not version:
            raise ContractError("REVIEW_TOOL_IDENTITY")
        validate_sha256(digest)
    for name, digest in package.identities.inputs:
        bounded_relative_path(name)
        validate_sha256(digest)
    if len(dict(package.identities.inputs)) != len(package.identities.inputs):
        raise ContractError("DUPLICATE_INPUT_IDENTITY")
    references = (
        package.artifact,
        package.policy,
        package.state.inventory,
        package.cost.raw_estimate,
        *package.profile.evidence,
        *package.cost.assumptions,
        *(item.basis for item in package.cost.coverage if item.basis is not None),
        *(
            item
            for item in (
                package.profile.last_known_good,
                package.profile.platform_cleanliness,
                package.profile.cleanup_spending,
            )
            if item is not None
        ),
    )
    for reference in references:
        bounded_relative_path(reference.path)
        validate_sha256(reference.sha256)
        if (
            reference.operation_id != package.operation_id
            or type(reference.byte_count) is not int
            or reference.byte_count <= 0
            or not reference.kind
            or not reference.producer
            or parse_utc_timestamp(reference.created_at, "evidence creation") > now
            or parse_utc_timestamp(reference.valid_until, "evidence expiry") < expires
        ):
            raise ContractError("EVIDENCE_BINDING_INVALID")
        reader.read(reference.path, reference.sha256, reference.byte_count)
    policy = decode_json_strict(
        reader.read(package.policy.path, package.policy.sha256, package.policy.byte_count)
    )
    purge = package.action is Action.PURGE_SANDBOX
    policy_schema = "w5-004.purge-policy-result.v2" if purge else "w5-004.policy-result.v2"
    if (
        not isinstance(policy, dict)
        or set(policy)
        != {
            "schema_version",
            "allow",
            "findings",
            "input_sha256",
            "policy_sha256",
            "exceptions_sha256",
        }
        or policy.get("schema_version") != policy_schema
    ):
        raise ContractError("POLICY_EVIDENCE_MALFORMED")
    inputs = dict(package.identities.inputs)
    if (
        policy["allow"] is not True
        or policy["findings"] != []
        or any(
            policy[key] != inputs.get(path)
            for key, path in (
                (
                    "input_sha256",
                    "review/purge-inventory.json" if purge else "review/normalized-plan.json",
                ),
                (
                    "policy_sha256",
                    "tools/platformctl/destroy.py" if purge else "policies/opa/terraform_plan.rego",
                ),
                ("exceptions_sha256", "policies/opa/exceptions.json"),
            )
        )
    ):
        raise ContractError("POLICY_NOT_BOUND_OR_ALLOWED")
    if package.summary != package.profile.rules or not package.summary:
        raise ContractError("ACTION_PROFILE_NOT_EXACT")
    addresses = [rule.address for rule in package.summary]
    if len(addresses) != len(set(addresses)):
        raise ContractError("DUPLICATE_RESOURCE_ACTION")
    profile = package.profile.profile
    for rule in package.summary:
        if (
            not rule.address
            or not rule.resource_type
            or rule.actions
            not in {
                ("create",),
                ("read",),
                ("no-op",),
                ("update",),
                ("delete",),
            }
        ):
            raise ContractError("ACTION_OR_REPLACEMENT_NOT_APPROVED")
        if profile is ChangeProfile.INITIAL and rule.actions not in {
            ("create",),
            ("read",),
            ("no-op",),
        }:
            raise ContractError("INITIAL_PROFILE_MUTATION")
        if profile is ChangeProfile.PARTIAL_RECOVERY:
            if not package.profile.evidence or rule.actions == ("delete",):
                raise ContractError("RECOVERY_PROFILE_INCOMPLETE")
            if rule.actions == ("update",) and (
                not rule.update_paths or rule.delta_rule not in {"EXPIRES_AT", "RUNTIME_IAM_EXPIRY"}
            ):
                raise ContractError("RECOVERY_DELTA_NOT_APPROVED")
        if profile is ChangeProfile.DESTROY and rule.actions not in {
            ("delete",),
            ("no-op",),
            ("read",),
        }:
            raise ContractError("DESTROY_PROFILE_ACTION")
        if profile is ChangeProfile.PURGE and (
            rule.resource_type != "aws_s3_bucket"
            or rule.actions != ("update",)
            or rule.update_paths != ("object_versions", "delete_markers", "multipart_uploads")
            or rule.delta_rule != "EXACT_PURGE_INVENTORY"
            or len(package.summary) != 1
        ):
            raise ContractError("PURGE_PROFILE_NOT_EXACT")
    allowed_profiles = {
        Action.BOOTSTRAP_APPLY: {ChangeProfile.INITIAL, ChangeProfile.PARTIAL_RECOVERY},
        Action.PLATFORM_APPLY: {ChangeProfile.INITIAL, ChangeProfile.PARTIAL_RECOVERY},
        Action.INFRASTRUCTURE_ROLLBACK: {ChangeProfile.ROLLBACK},
        Action.PLATFORM_DESTROY: {ChangeProfile.DESTROY},
        Action.BOOTSTRAP_DESTROY: {ChangeProfile.DESTROY},
        Action.PURGE_SANDBOX: {ChangeProfile.PURGE},
    }
    if profile not in allowed_profiles[package.action]:
        raise ContractError("ACTION_PROFILE_MISMATCH")
    expected_kind = "purge-inventory" if profile is ChangeProfile.PURGE else "saved-plan"
    if package.artifact.kind != expected_kind:
        raise ContractError("ARTIFACT_KIND_MISMATCH")
    if profile is ChangeProfile.ROLLBACK:
        _validate_last_known_good(package, reader, now)
    validate_native_prerequisites(package.profile, package.state, reader, now)
    validate_cycle_prerequisites(
        package.profile,
        package.state,
        reader,
        now,
        prepared_at=package.prepared_at,
        resource_expires_at=package.resource_expires_at,
        action=package.action,
        identities=package.identities,
    )
    if profile is ChangeProfile.PURGE:
        from .destroy import validate_purge_review

        validate_purge_review(package, reader, now)
    if package.action is Action.BOOTSTRAP_DESTROY and package.profile.platform_cleanliness is None:
        raise ContractError("BOOTSTRAP_LAST_PROOF_MISSING")
    if package.action is Action.BOOTSTRAP_DESTROY:
        _validate_platform_cleanliness(package, reader, now)
        _validate_bootstrap_retention(package, reader, now)
    if package.native.incomplete_services or not package.native.covered_services:
        raise ContractError("NATIVE_COVERAGE_INCOMPLETE")
    if (
        package.native.operation_id != package.operation_id
        or package.native.account_id != package.account_id
        or package.native.region != package.region
        or set(addresses) != {item.address for item in package.native.entries}
        or len(package.native.entries) != len(addresses)
        or any(
            item.resource_type != rule.resource_type
            for item, rule in zip(
                sorted(package.native.entries, key=lambda entry: entry.address),
                sorted(package.summary, key=lambda entry: entry.address),
                strict=True,
            )
        )
        or any(
            item.ownership != "PROJECT_MANAGED" or item.presence == "INDETERMINATE"
            for item in package.native.entries
        )
    ):
        raise ContractError("NATIVE_OWNERSHIP_OR_INVENTORY")
    _fresh(package.native.observed_at, now, 900)
    from .cost import (
        reconcile_charging_bases,
        reconcile_cost_inventory,
        reconcile_incurred_coverage,
        validate_cost_result_v2,
    )

    if not purge:
        covered = {
            entry.address for entry in package.cost.coverage if entry.scope == package.target
        }
        expected_cost = {
            rule.address
            for rule in package.summary
            if rule.resource_type != "aws_iam_policy_document"
        }
        if covered != expected_cost:
            raise ContractError("REVIEW_COST_RESOURCE_COVERAGE_MISMATCH")
        reconcile_cost_inventory(package.cost, package.target, reader, now)

    if package.cost.status is Outcome.PASS and not purge:
        validate_cost_result_v2(
            package.cost,
            package.artifact.sha256,
            now,
            reader=reader,
            scope=package.target,
            state_lineage=package.state.lineage,
            configuration_sha256=dict(package.identities.inputs).get(
                "configs/lifecycle/w5-004.json"
            ),
            environment=package.environment,
        )
        reconcile_charging_bases(package.cost, reader, now, scope=package.target)
        reconcile_incurred_coverage(package.cost, package.native, package.target, reader)
    elif package.cost.status is Outcome.INDETERMINATE:
        _validate_conservative_cost_bound(package, reader, now)
    else:
        raise ContractError("COST_REVIEW_FAILED")


def validate_native_prerequisites(
    profile: RecoveryProfile,
    state: StateEvidence,
    reader: EvidenceReader,
    now: datetime,
) -> tuple[NativePrerequisiteEvidence, ...]:
    """Do not interpret a missing external role or unresolved log policy as permission."""
    from .aws_inventory import NativeReadSpec
    from .lifecycle_io import decode_json_strict, decode_operational_record, decode_record
    from .lifecycle_models import NativePrerequisiteEvidence

    domains = [
        rule
        for rule in profile.rules
        if rule.resource_type == "aws_opensearch_domain" and rule.actions != ("delete",)
    ]
    policies = [
        rule
        for rule in profile.rules
        if rule.resource_type == "aws_cloudwatch_log_resource_policy"
        and rule.actions != ("delete",)
    ]
    required = set()
    if domains:
        required.add("opensearch-service-role")
        if profile.service_role_treatment != "PRESENT_EXCLUDED_OWNER_MANAGED":
            raise ContractError("OPENSEARCH_SERVICE_ROLE_REQUIRES_SEPARATE_DISPOSITION")
    if policies:
        required.add("log-policy-reconciliation")
        if profile.log_policy_resolution != "STATE_AND_NATIVE_MATCH":
            raise ContractError("LOG_POLICY_RESOLUTION_REQUIRED")
    records: list[NativePrerequisiteEvidence] = []
    for kind in sorted(required):
        references = [ref for ref in profile.evidence if ref.kind == kind]
        if len(references) != 1:
            raise ContractError("NATIVE_PREREQUISITE_EVIDENCE_REQUIRED")
        reference = references[0]
        record = decode_operational_record(
            reader.read(reference.path, reference.sha256, reference.byte_count),
            NativePrerequisiteEvidence,
        )
        _fresh(record.observed_at, now, 900)
        if (
            record.operation_id != reference.operation_id
            or record.kind != kind
            or record.account_id != APPROVED_AWS_ACCOUNT_ID
            or record.region != APPROVED_AWS_REGION
            or record.state_sha256 != state.sha256
            or parse_utc_timestamp(record.valid_until, "prerequisite expiry") <= now
        ):
            raise ContractError("NATIVE_PREREQUISITE_IDENTITY_OR_FRESHNESS")
        probe = decode_record(decode_json_strict(record.probe_json.encode("utf-8")), NativeReadSpec)
        if (probe.address, probe.resource_type, probe.expected_native_identity) != (
            record.address,
            record.resource_type,
            record.native_identity,
        ):
            raise ContractError("NATIVE_PREREQUISITE_PROBE_MISMATCH")
        expected = decode_json_strict(record.expected_fields_json.encode("utf-8"))
        if not isinstance(expected, dict) or not expected:
            raise ContractError("NATIVE_PREREQUISITE_CONFIGURATION_REQUIRED")
        if kind == "opensearch-service-role":
            if (
                record.resource_type != "aws_iam_service_linked_role"
                or record.ownership != "OWNER_MANAGED"
                or record.presence != "PRESENT"
                or record.state_presence != "EXCLUDED"
                or probe.service != "iam"
                or probe.method != "get_role"
                or not record.native_identity.startswith(
                    "arn:aws:iam::" + APPROVED_AWS_ACCOUNT_ID + ":role/aws-service-role/"
                )
                or "AssumeRolePolicyDocument.@policy_sha256" not in expected
            ):
                raise ContractError("OPENSEARCH_SERVICE_ROLE_UNPROVEN")
        else:
            matched = [rule for rule in policies if rule.address == record.address]
            if (
                len(matched) != 1
                or record.ownership != "PROJECT_MANAGED"
                or record.resource_type != "aws_cloudwatch_log_resource_policy"
                or probe.service != "logs"
                or probe.method != "describe_resource_policies"
                or record.presence != record.state_presence
                or record.presence != ("ABSENT" if matched[0].actions == ("create",) else "PRESENT")
                or "policyDocument.@policy_sha256" not in expected
            ):
                raise ContractError("LOG_POLICY_STATE_NATIVE_MISMATCH")
        records.append(record)
    return tuple(records)


def _validate_platform_cleanliness(
    package: ReviewPackage,
    reader: EvidenceReader,
    now: datetime,
) -> None:
    from .lifecycle_io import decode_operational_record
    from .lifecycle_models import InventoryResult
    from .verify_clean import _verify_kms_retention

    reference = package.profile.platform_cleanliness
    if reference is None:
        raise ContractError("BOOTSTRAP_LAST_PROOF_MISSING")
    proof = decode_operational_record(
        reader.read(reference.path, reference.sha256, reference.byte_count), InventoryResult
    )
    _fresh(proof.observed_at, now, 900)
    if (
        proof.account_id != package.account_id
        or proof.region != package.region
        or (
            proof.operation_id != package.operation_id
            or proof.incomplete_services
            or not proof.covered_services
            or not proof.entries
            or parse_utc_timestamp(proof.valid_until, "platform cleanup expiry") <= now
            or len({entry.address for entry in proof.entries}) != len(proof.entries)
        )
    ):
        raise ContractError("BOOTSTRAP_LAST_REMOVAL_UNPROVEN")
    schedules = tuple(
        item for item in package.profile.evidence if item.kind == "kms-scheduling-observation"
    )
    for entry in proof.entries:
        if entry.ownership != "PROJECT_MANAGED" or entry.cost_bearing is not False:
            raise ContractError("BOOTSTRAP_LAST_RETAINED_LIABILITY")
        if entry.resource_type == "aws_kms_key" and entry.presence == "PENDING_DELETION":
            _verify_kms_retention(package, entry, schedules, reader, now)
        elif (
            entry.presence == "EVALUATION_ONLY" and entry.resource_type == "aws_iam_policy_document"
        ):
            continue
        elif entry.presence != "ABSENT":
            raise ContractError("BOOTSTRAP_LAST_ACTIVE_OR_UNKNOWN_RESOURCE")


def _validate_last_known_good(
    package: ReviewPackage,
    reader: EvidenceReader,
    now: datetime,
) -> None:
    from .lifecycle_io import decode_operational_record
    from .lifecycle_models import LastKnownGoodEvidence, OperationPhase, OperationResultV2, Outcome

    reference = package.profile.last_known_good
    if reference is None:
        raise ContractError("LAST_KNOWN_GOOD_UNAVAILABLE")
    known = decode_operational_record(
        reader.read(reference.path, reference.sha256, reference.byte_count), LastKnownGoodEvidence
    )
    if (
        known.operation_id != package.operation_id
        or known.account_id != package.account_id
        or known.region != package.region
        or known.environment != package.environment
        or known.source_sha256 != package.identities.working_sha256
        or known.approver != APPROVER
        or not known.deployment_id
        or parse_utc_timestamp(known.approved_at, "known-good approval") > now
    ):
        raise ContractError("LAST_KNOWN_GOOD_BINDING_INVALID")
    proof = known.verification
    verified = decode_operational_record(
        reader.read(proof.path, proof.sha256, proof.byte_count), OperationResultV2
    )
    if (
        verified.operation_id != known.deployment_id
        or verified.state is not OperationPhase.POST_EXECUTION_VERIFIED
        or verified.classification is not Outcome.PASS
        or verified.verification is not Outcome.PASS
        or verified.exit_code != 0
        or not verified.mutation_started
    ):
        raise ContractError("LAST_KNOWN_GOOD_NOT_VERIFIED")


def _validate_bootstrap_retention(
    package: ReviewPackage,
    reader: EvidenceReader,
    now: datetime,
) -> None:
    from .lifecycle_io import decode_operational_record
    from .lifecycle_models import RetentionDecision

    candidates = [ref for ref in package.profile.evidence if ref.kind == "state-audit-retention"]
    if len(candidates) != 1:
        raise ContractError("BOOTSTRAP_STATE_AUDIT_RETENTION_REQUIRED")
    ref = candidates[0]
    decision = decode_operational_record(
        reader.read(ref.path, ref.sha256, ref.byte_count), RetentionDecision
    )
    keys = tuple(
        sorted(
            rule.address
            for rule in package.summary
            if rule.resource_type == "aws_kms_key" and rule.actions == ("delete",)
        )
    )
    if (
        decision.operation_id != package.operation_id
        or decision.account_id != package.account_id
        or decision.region != package.region
        or decision.environment != package.environment
        or decision.state_sha256 != package.state.sha256
        or decision.approver != APPROVER
        or decision.follow_up_owner != APPROVER
        or decision.kms_window_days != 7
        or decision.kms_addresses != keys
        or not decision.retained_artifacts
        or parse_utc_timestamp(decision.approved_at, "retention approval") > now
        or parse_utc_timestamp(decision.expires_at, "retention expiry")
        < parse_utc_timestamp(package.expires_at, "review expiry")
        or not {"retained-state", "retained-audit"}.issubset(
            {artifact.kind for artifact in decision.retained_artifacts}
        )
    ):
        raise ContractError("BOOTSTRAP_RETENTION_OR_KMS_TREATMENT_INVALID")
    for artifact in decision.retained_artifacts:
        if artifact.operation_id != package.operation_id:
            raise ContractError("RETENTION_OPERATION_MISMATCH")
        reader.read(artifact.path, artifact.sha256, artifact.byte_count)


def validate_recovery_scope_declaration(value: object) -> None:
    from .aws_inventory import PREREQUISITE_POLICY, PREREQUISITE_ROLES
    from .lifecycle_models import RecoveryScopeDeclaration

    if not isinstance(value, RecoveryScopeDeclaration) or (
        value.cycle != "W5-CYCLE-A"
        or value.account_id != APPROVED_AWS_ACCOUNT_ID
        or set(value.resources) != {*PREREQUISITE_ROLES, PREREQUISITE_POLICY}
        or len(value.resources) != 13
        or value.ownership_certified is not False
        or value.intent != "NO_ASSUME_MODIFY_DELETE_OR_INTENTIONAL_USE_UNLESS_REVIEWED_DEPENDENCY"
        or not value.approval_path
    ):
        raise ContractError("RECOVERY_SCOPE_DECLARATION_INVALID")
    validate_sha256(value.approval_sha256)


def validate_prerequisite_terms(
    value: object,
    now: datetime,
    *,
    prepared_at: str | None = None,
    resource_expires_at: str | None = None,
    deployment: bool = False,
) -> None:
    """Retention is a fixed decision, never a freshness or destruction exception."""
    from .lifecycle_io import canonical_json_bytes
    from .lifecycle_models import PrerequisiteTerms

    if not isinstance(value, PrerequisiteTerms) or (
        canonical_json_bytes(value) != canonical_json_bytes(PrerequisiteTerms())
    ):
        raise ContractError("PREREQUISITE_TERMS_CHANGED")
    deadline = parse_utc_timestamp(value.retention_deadline, "bootstrap retention")
    if now >= deadline:
        raise ContractError("BOOTSTRAP_RETENTION_DEADLINE_PASSED")
    if prepared_at is not None:
        prepared = parse_utc_timestamp(prepared_at, "preparation")
        if prepared > now or prepared + timedelta(seconds=value.operating_seconds) >= deadline:
            raise ContractError("OPERATING_ENVELOPE_OUTSIDE_RETENTION")
        milestone = value.deployment_seconds if deployment else value.operating_seconds
        if now >= prepared + timedelta(seconds=milestone):
            raise ContractError("OPERATING_MILESTONE_EXHAUSTED")
        if resource_expires_at is not None and (
            parse_utc_timestamp(resource_expires_at, "resource expiry")
            != prepared + timedelta(seconds=value.resource_expiry_seconds)
        ):
            raise ContractError("OPERATING_RESOURCE_EXPIRY_CHANGED")


def validate_cycle_prerequisites(
    profile: RecoveryProfile,
    state: StateEvidence,
    reader: EvidenceReader,
    now: datetime,
    *,
    prepared_at: str,
    resource_expires_at: str | None = None,
    action: Action = Action.PLATFORM_APPLY,
    identities: IdentityBundle | None = None,
) -> None:
    """One evidence consumer shared by preparation, review and direct dispatch."""
    from .aws_inventory import (
        PREREQUISITE_CHECK_IDS,
        PREREQUISITE_CORRECTION_CHECK_IDS,
        PREREQUISITE_CORRECTION_OPERATION,
    )
    from .lifecycle_io import decode_json_strict, decode_record
    from .lifecycle_models import ChangeProfile, PrerequisiteTerms

    if profile.profile is not ChangeProfile.PARTIAL_RECOVERY:
        return
    # Earlier immutable reviews remain historical; their freshness checks still apply.
    if parse_utc_timestamp(prepared_at, "preparation") < datetime(2026, 9, 13, tzinfo=UTC):
        return
    refs = [ref for ref in profile.evidence if ref.kind == "cycle-prerequisite-resolution"]
    if len(refs) != 1:
        raise ContractError("CYCLE_PREREQUISITE_EVIDENCE_REQUIRED")
    ref = refs[0]
    _fresh(ref.created_at, now, 900)
    if parse_utc_timestamp(ref.valid_until, "prerequisite freshness") <= now:
        raise ContractError("CYCLE_PREREQUISITE_EVIDENCE_EXPIRED")
    report = decode_json_strict(reader.read(ref.path, ref.sha256, ref.byte_count))
    correction = (
        isinstance(report, dict)
        and report.get("schema_version") == "w5-004.prerequisite-resolution.v2"
    )
    check_ids = PREREQUISITE_CORRECTION_CHECK_IDS if correction else PREREQUISITE_CHECK_IDS
    if not isinstance(report, dict) or (
        report.get("schema_version")
        != (
            "w5-004.prerequisite-resolution.v2"
            if correction
            else "w5-004.prerequisite-resolution.v1"
        )
        or report.get("operation_id")
        != (PREREQUISITE_CORRECTION_OPERATION if correction else "w5-004-prerequisite-evidence-001")
        or report.get("account_id") != APPROVED_AWS_ACCOUNT_ID
        or report.get("region") != APPROVED_AWS_REGION
        or report.get("exit_code") != 0
        or type(report.get("exit_code")) is not int
        or report.get("mutation_started") is not False
    ):
        raise ContractError("CYCLE_PREREQUISITES_UNRESOLVED")
    terms = decode_record(report.get("terms"), PrerequisiteTerms)
    validate_prerequisite_terms(
        terms,
        now,
        prepared_at=prepared_at,
        resource_expires_at=resource_expires_at,
        deployment=action is Action.PLATFORM_APPLY,
    )
    states = report.get("states")
    platform = states.get("platform") if isinstance(states, dict) else None
    bootstrap = states.get("bootstrap") if isinstance(states, dict) else None
    if (
        not isinstance(platform, dict)
        or not isinstance(bootstrap, dict)
        or (
            (platform.get("lineage"), platform.get("serial"), platform.get("sha256"))
            != (state.lineage, state.serial, state.sha256)
            or bootstrap.get("lineage") != terms.bootstrap_lineage
            or bootstrap.get("serial") != terms.bootstrap_serial
            or identities is None
            or dict(identities.inputs).get("prerequisite/bootstrap-state")
            != bootstrap.get("sha256")
        )
    ):
        raise ContractError("CYCLE_PREREQUISITE_STATE_CHANGED")
    checks = report.get("checks")
    if (
        not isinstance(checks, list)
        or len(checks) != len(check_ids)
        or any(
            not isinstance(check, dict)
            or (check.get("mandatory") is True and check.get("status") != "PASS")
            for check in checks
        )
    ):
        raise ContractError("CYCLE_PREREQUISITES_UNRESOLVED")

    if {check.get("check_id") for check in checks} != set(check_ids) or any(
        check.get("mandatory") is not True for check in checks
    ):
        raise ContractError("CYCLE_PREREQUISITE_CHECKS_INCOMPLETE")
    if correction:
        from .aws_inventory import PREREQUISITE_LOG_ACTIONS, PREREQUISITE_LOG_NAMES

        details = {row["check_id"]: dict(row.get("details", [])) for row in checks}
        decisions: dict[str, bool] = {}
        for action_name in PREREQUISITE_LOG_ACTIONS:
            item = details.get("authorization/" + action_name, {})
            try:
                findings = decode_json_strict(item.get("findings", "null").encode())
            except (AttributeError, ContractError) as exc:
                raise ContractError("CYCLE_AUTHORIZATION_UNRESOLVED") from exc
            targets = {
                "arn:aws:logs:ap-southeast-1:526338061652:log-group:"
                + name
                + ("" if action_name == "logs:TagResource" else ":*")
                for name in PREREQUISITE_LOG_NAMES
            }
            if (
                item.get("coverage_complete") != "true"
                or item.get("issues") != "[]"
                or item.get("missing_context") != "[]"
                or not isinstance(findings, list)
                or len(findings) != 4
                or any(not isinstance(row, dict) for row in findings)
                or {row.get("resource") for row in findings} != targets
                or any(
                    row.get("decision") not in {"allowed", "explicitDeny", "implicitDeny"}
                    or row.get("missing_context") != []
                    for row in findings
                )
            ):
                raise ContractError("CYCLE_AUTHORIZATION_UNRESOLVED")
            decisions[action_name] = all(row["decision"] == "allowed" for row in findings)
        if not (
            (decisions["logs:TagResource"] or decisions["logs:TagLogGroup"])
            and all(
                decisions[name]
                for name in (
                    "logs:CreateLogGroup",
                    "logs:AssociateKmsKey",
                    "logs:PutRetentionPolicy",
                )
            )
        ):
            raise ContractError("CYCLE_AUTHORIZATION_UNRESOLVED")
        summary = details.get("authorization/summary", {})
        if (
            summary.get("tagging_either_permission") != "true"
            or summary.get("other_actions_allowed") != "true"
        ):
            raise ContractError("CYCLE_AUTHORIZATION_UNRESOLVED")
        kms = details.get("authorization/kms", {})
        if (
            kms.get("policy_matches_bound_state") != "true"
            or kms.get("exact_logs_statement") != "true"
        ):
            raise ContractError("CYCLE_KMS_UNRESOLVED")


def _validate_conservative_cost_bound(
    package: ReviewPackage, reader: EvidenceReader, now: datetime
) -> None:
    from decimal import Decimal, InvalidOperation

    from .cost import validate_monthly_amendment, verified_lifecycle_ceiling
    from .lifecycle_io import decode_operational_record
    from .lifecycle_models import CostBoundV2, CoverageClass

    monthly_informational = validate_monthly_amendment(
        package.cost.monthly_amendment,
        reader=reader,
        now=now,
        operation_id=package.operation_id,
        scope=package.target,
        state_lineage=package.state.lineage,
        configuration_sha256=dict(package.identities.inputs).get("configs/lifecycle/w5-004.json"),
        environment=package.environment,
    )

    candidates = tuple(
        reference
        for reference in package.profile.evidence
        if reference.kind == "conservative-cost-bound"
    )
    lifecycle_ceiling = verified_lifecycle_ceiling(
        package.cost.lifecycle_amendment,
        reader=reader,
        now=now,
        operation_id=package.operation_id,
        scope=package.target,
        state_lineage=package.state.lineage,
        configuration_sha256=dict(package.identities.inputs).get("configs/lifecycle/w5-004.json"),
        environment=package.environment,
    )
    if package.profile.cleanup_spending is not None:
        candidates += (package.profile.cleanup_spending,)
    if len(candidates) != 1 or any(
        entry.classification is CoverageClass.ERROR for entry in package.cost.coverage
    ):
        raise ContractError("COST_BOUND_REQUIRED")
    reference = candidates[0]
    bound = decode_operational_record(
        reader.read(reference.path, reference.sha256, reference.byte_count), CostBoundV2
    )
    if (
        bound.operation_id != package.operation_id
        or bound.action is not package.action
        or bound.artifact_sha256 != package.artifact.sha256
        or bound.account_id != package.account_id
        or bound.currency != "USD"
        or bound.scope != "TOTAL_LIFECYCLE_INCLUDING_INCURRED_AND_RETENTION"
        or bound.approver != APPROVER
        or not bound.covered_addresses
        or set(bound.covered_addresses)
        != {entry.scope + ":" + entry.address for entry in package.cost.coverage}
        or len(bound.covered_addresses) != len(set(bound.covered_addresses))
        or parse_utc_timestamp(bound.approved_at, "cost approval") > now
        or parse_utc_timestamp(bound.expires_at, "cost expiry")
        < parse_utc_timestamp(package.expires_at, "review expiry")
    ):
        raise ContractError("COST_BOUND_BINDING_INVALID")
    try:
        lifecycle = Decimal(bound.lifecycle_upper_usd)
        monthly = Decimal(bound.monthly_upper_usd)
    except InvalidOperation as exc:
        raise ContractError("COST_BOUND_AMOUNT_INVALID") from exc
    if (
        not lifecycle.is_finite()
        or not monthly.is_finite()
        or not 0 <= lifecycle <= lifecycle_ceiling
        or monthly < 0
        or (monthly > 60 and not monthly_informational)
    ):
        raise ContractError("COST_BOUND_EXCEEDS_CEILING")
    basis = reader.read(bound.basis.path, bound.basis.sha256, bound.basis.byte_count)
    if any(ref.kind == "cycle-prerequisite-resolution" for ref in package.profile.evidence):
        from .cost import validate_prerequisite_cost_bound

        validate_prerequisite_cost_bound(basis, lifecycle, now, reader)


_EXECUTION_CONTEXT_SEAL = object()


class VerifiedExecutionContext:
    """Coordinator-issued capability; adapters reobserve identities before dispatch."""

    def __init__(
        self,
        seal: object,
        package: ReviewPackage,
        approval: ApprovalRecordV2,
        reader: EvidenceReader,
        revalidator: ExecutionRevalidator,
        clock: Clock,
    ) -> None:
        if seal is not _EXECUTION_CONTEXT_SEAL:
            raise ApprovalError("VERIFIED_CONTEXT_REQUIRED")
        self.package = package
        self.approval = approval
        self._reader = reader
        self._revalidator = revalidator
        self._clock = clock
        from threading import Lock

        self._dispatch_lock = Lock()
        self._dispatch_started = False

    def revalidate(self, action: Action, artifact_sha256: str, *, consumed: bool) -> None:
        """Reject stale or drifted authority at direct and lowest mutation boundaries."""
        now = self._clock.now()
        if action is not self.package.action or artifact_sha256 != self.package.artifact.sha256:
            raise ApprovalError("DISPATCH_ACTION_OR_ARTIFACT")
        validate_review_package(self.package, now=now, reader=self._reader)
        _validate_v2_approval(self.package, self.approval, now)
        observed = self._revalidator.observe(self.package)
        now = self._clock.now()
        validate_review_package(self.package, now=now, reader=self._reader)
        _validate_v2_approval(self.package, self.approval, now)
        _fresh(observed.identity_observed_at, now, 60)
        _fresh(observed.state.observed_at, now, 60)
        _fresh(observed.native.observed_at, now, 900)
        if (
            observed.identities != self.package.identities
            or observed.account_id != self.package.account_id
            or observed.region != self.package.region
            or observed.caller != self.package.caller
            or (
                observed.state.backend,
                observed.state.lineage,
                observed.state.serial,
                observed.state.sha256,
                observed.state.remote_version,
            )
            != (
                self.package.state.backend,
                self.package.state.lineage,
                self.package.state.serial,
                self.package.state.sha256,
                self.package.state.remote_version,
            )
            or observed.native.incomplete_services
            or observed.native.covered_services != self.package.native.covered_services
        ):
            raise ApprovalError("DISPATCH_IDENTITY_DRIFT")

        def inventory_shape(value: DispatchObservation) -> tuple[tuple[object, ...], ...]:
            return tuple(
                (
                    entry.address,
                    entry.resource_type,
                    entry.native_identity,
                    entry.state_identity,
                    entry.ownership,
                    entry.presence,
                    entry.configuration,
                    entry.cost_bearing,
                    entry.scheduled_deletion_at,
                )
                for entry in value.native.entries
            )

        expected = type(observed)(
            self.package.identities,
            self.package.state,
            self.package.native,
            self.package.account_id,
            self.package.region,
            self.package.caller,
            observed.identity_observed_at,
        )
        if inventory_shape(observed) != inventory_shape(expected):
            raise ApprovalError("DISPATCH_NATIVE_DRIFT")
        recorded = self._revalidator.approval_consumed(
            self.package.operation_id, self.approval.approval_id
        )
        if recorded is not consumed:
            raise ApprovalError("DISPATCH_DURABLE_STATE_MISMATCH")

    def current_timestamp(self) -> str:
        """Read the same bound clock for a post-dispatch durable observation."""
        return self._clock.now().replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def artifact_bytes(self) -> bytes:
        """Return only the exact bound artifact after its normal identity checks."""
        reference = self.package.artifact
        return self._reader.read(reference.path, reference.sha256, reference.byte_count)

    @property
    def dispatch_started(self) -> bool:
        """Whether this capability has reached its one-time process-dispatch boundary."""
        with self._dispatch_lock:
            return self._dispatch_started

    def claim_dispatch(self, action: Action, artifact_sha256: str) -> None:
        """Prevent repeated low-level dispatch through one already-consumed capability."""
        self.revalidate(action, artifact_sha256, consumed=True)
        with self._dispatch_lock:
            if self._dispatch_started:
                raise ApprovalError("CAPABILITY_DISPATCH_ALREADY_STARTED")
            self._dispatch_started = True


def _validate_v2_approval(
    package: ReviewPackage, approval: ApprovalRecordV2, now: datetime
) -> None:
    from .lifecycle_io import canonical_json_bytes, sha256_bytes
    from .lifecycle_models import OPERATIONAL_SCHEMA_VERSION

    if approval.schema_version != OPERATIONAL_SCHEMA_VERSION:
        raise ApprovalError("V2_APPROVAL_REQUIRED")
    expected = (
        package.action,
        package.profile.profile,
        package.account_id,
        package.region,
        package.environment,
        package.target,
        sha256_bytes(canonical_json_bytes(package)),
        package.artifact.kind,
        package.artifact.sha256,
    )
    actual = (
        approval.action,
        approval.profile,
        approval.account_id,
        approval.region,
        approval.environment,
        approval.target,
        approval.review_sha256,
        approval.artifact_kind,
        approval.artifact_sha256,
    )
    approved = parse_utc_timestamp(approval.approved_at, "approval time")
    expires = parse_utc_timestamp(approval.expires_at, "approval expiry")
    if (
        actual != expected
        or approval.approver != APPROVER
        or approval.executor != EXECUTOR
        or approved > now
        or approved < parse_utc_timestamp(package.prepared_at, "prepared_at")
        or expires <= now
        or expires > parse_utc_timestamp(package.expires_at, "review expiry")
        or expires - approved > MAX_APPROVAL_LIFETIME
    ):
        raise ApprovalError("APPROVAL_BINDING_OR_WINDOW")
    validate_runtime_token(approval.approval_id, "approval_id")
    confirmation = (
        f"CONFIRM {approval.action.value} {approval.environment} {approval.target} "
        f"{approval.artifact_sha256} {approval.approval_id}"
    )
    if approval.confirmation != confirmation:
        raise ApprovalError("APPROVAL_CONFIRMATION")


def authorize_mutation(
    package: ReviewPackage,
    approval: ApprovalRecordV2,
    *,
    reader: EvidenceReader,
    revalidator: ExecutionRevalidator,
    clock: Clock,
) -> VerifiedExecutionContext:
    """Issue authority only after complete fresh review and unused-approval checks."""
    context = VerifiedExecutionContext(
        _EXECUTION_CONTEXT_SEAL, package, approval, reader, revalidator, clock
    )
    context.revalidate(package.action, package.artifact.sha256, consumed=False)
    return context


# W6-004 extends the lifecycle only through separately bound owner evidence.
W6_004_MAX_GOVERNANCE_LIFETIME = timedelta(hours=24)
W6_004_MAX_MUTATION_WINDOW = timedelta(hours=8)


def validate_w6_004_window(issued_at: datetime, expires_at: datetime) -> None:
    """Reject invalid or over-broad W6-004 approval windows."""

    if issued_at.tzinfo is None or expires_at.tzinfo is None:
        raise ApprovalError("W6_004_WINDOW_TIMEZONE_REQUIRED")
    duration = expires_at - issued_at
    if duration <= timedelta(0) or duration > W6_004_MAX_GOVERNANCE_LIFETIME:
        raise ApprovalError("W6_004_APPROVAL_WINDOW_INVALID")


def validate_temporary_iam_operation(value: TemporaryIamOperation, now: datetime) -> None:
    """Validate exact, source-bound temporary access without performing an IAM call."""
    from .lifecycle_models import W7_001_SCHEMA_VERSION, ControlResult, TemporaryIamOperation

    if (
        not isinstance(value, TemporaryIamOperation)
        or value.schema_version != W7_001_SCHEMA_VERSION
    ):
        raise ContractError("TEMPORARY_IAM_SCHEMA_REQUIRED")
    for digest in (
        value.source_sha256,
        value.before_state_sha256,
        value.after_state_sha256,
    ):
        if digest is not None:
            validate_sha256(digest)
    issued = parse_utc_timestamp(value.issued_at, "temporary IAM issued_at")
    expires = parse_utc_timestamp(value.expires_at, "temporary IAM expires_at")
    operation_expires = parse_utc_timestamp(
        value.operation_expires_at, "temporary IAM operation_expires_at"
    )
    if now.tzinfo is None or now.utcoffset() is None:
        raise ContractError("TEMPORARY_IAM_NOW_TIMEZONE_REQUIRED")
    if (
        issued > now
        or expires <= now
        or expires > operation_expires
        or expires - issued > timedelta(hours=1)
    ):
        raise ContractError("TEMPORARY_IAM_EXPIRY_INVALID")
    if (
        not value.operation_id
        or not value.approval_id
        or not value.principal.startswith("arn:")
        or not value.actions
        or not value.resources
        or any("*" in item for item in (*value.actions, *value.resources))
        or len(value.actions) != len(set(value.actions))
        or len(value.resources) != len(set(value.resources))
        or len(value.conditions) != len(set(value.conditions))
    ):
        raise ContractError("TEMPORARY_IAM_SCOPE_INVALID")
    if value.restoration_status is ControlResult.PASS:
        if value.after_state_sha256 != value.before_state_sha256:
            raise ContractError("TEMPORARY_IAM_RESTORATION_MISMATCH")
        if value.partial_failure_cleanup is not ControlResult.PASS:
            raise ContractError("TEMPORARY_IAM_PARTIAL_CLEANUP_UNPROVEN")
