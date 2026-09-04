"""Strict offline contracts for owner-gated platform lifecycle actions."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Protocol, cast

APPROVAL_SCHEMA_VERSION = "1.0"
APPROVER = "Gyan-Prakash-Rai"
EXECUTOR = "Gyan-Prakash-Rai"
MAX_APPROVAL_LIFETIME = timedelta(minutes=60)
MAX_SANDBOX_RESOURCE_LIFETIME = timedelta(hours=24)

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

    BOOTSTRAP = "BOOTSTRAP"
    DEPLOY = "DEPLOY"
    ROLLBACK = "ROLLBACK"
    DESTROY_SAFE = "DESTROY-SAFE"
    PURGE_SANDBOX = "PURGE-SANDBOX"


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


def parse_utc_timestamp(value: str, field_name: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp that uses the required Z suffix."""
    if "T" not in value or not value.endswith("Z") or value in _PLACEHOLDERS:
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
    resource_expires_at: str | None = None


def validate_resource_expires_at(
    value: str,
    *,
    approval_time: datetime,
    deployment_time: datetime,
    creation_time: datetime,
) -> datetime:
    """Validate the runtime sandbox expiry without providing a default."""
    expires_at = parse_utc_timestamp(value, "resource ExpiresAt")
    if expires_at <= approval_time or expires_at <= deployment_time:
        raise ContractError("resource ExpiresAt must follow approval and deployment time")
    if expires_at <= creation_time:
        raise ContractError("resource ExpiresAt must follow resource creation time")
    if expires_at - creation_time > MAX_SANDBOX_RESOURCE_LIFETIME:
        raise ContractError("resource ExpiresAt exceeds the 24-hour sandbox lifetime")
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
    *,
    require_resource_expiry: bool,
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

    if require_resource_expiry:
        if request.resource_expires_at is None:
            raise ContractError("resource ExpiresAt is required for resource-creation intent")
        validate_resource_expires_at(
            request.resource_expires_at,
            approval_time=approval.approved_at_datetime,
            deployment_time=now,
            creation_time=now,
        )
        canonical_resource_tags(request.environment, request.resource_expires_at)
