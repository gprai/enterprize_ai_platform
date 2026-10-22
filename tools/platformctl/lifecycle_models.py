"""Typed deterministic W5-004 lifecycle records and outcomes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from pathlib import Path

from .contracts import (
    APPROVED_AWS_ACCOUNT_ID,
    APPROVED_AWS_REGION,
    APPROVED_ENVIRONMENT,
    Action,
    ContractError,
    generated_resource_expires_at,
    parse_utc_timestamp,
    validate_aws_account_id,
    validate_aws_region,
    validate_runtime_token,
    validate_sha256,
)

LIFECYCLE_SCHEMA_VERSION = "w5-004.lifecycle.v1"
TASK_ID = "W5-004"
LIFECYCLE_CYCLE_ID = "W5-CYCLE-A"
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class Outcome(StrEnum):
    """The only permitted lifecycle result classifications."""

    PASS = "PASS"  # noqa: S105 - lifecycle outcome, not credential material
    FAIL = "FAIL"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


class PlanAction(StrEnum):
    """Canonical action classes derived from Terraform plan JSON."""

    CREATE = "create"
    READ = "read"
    NO_OP = "no-op"
    UPDATE = "update"
    REPLACE = "replace"
    DELETE = "delete"


class ResourceDisposition(StrEnum):
    """Cleanup classifications kept distinct from rollback."""

    ACTIVE = "ACTIVE"
    REMOVED = "REMOVED"
    RETAINED = "RETAINED"
    PENDING_DELETION = "PENDING_DELETION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ToolIdentity:
    """Exact executable version and optional artifact identity."""

    name: str
    version: str
    executable_sha256: str | None = None


@dataclass(frozen=True)
class PlanActionRecord:
    """One address and its normalized action."""

    address: str
    resource_type: str
    action: PlanAction


@dataclass(frozen=True)
class PlanSummary:
    """Deterministic create/read/no-op/update/replace/delete summary."""

    records: tuple[PlanActionRecord, ...]

    def count(self, action: PlanAction) -> int:
        """Count one action class."""
        return sum(record.action is action for record in self.records)

    @property
    def initially_eligible(self) -> bool:
        """Initial plans may only create, read, or perform no operation."""
        permitted = {PlanAction.CREATE, PlanAction.READ, PlanAction.NO_OP}
        return all(record.action in permitted for record in self.records)


@dataclass(frozen=True)
class PreparedResourceExpiryInput:
    """One generated external tfvars override bound to a captured plan time."""

    path: Path
    environment: str
    prepared_at: str
    resource_expires_at: str
    sha256: str

    def validate(self) -> None:
        """Reject timestamp, hash, or deterministic-lifetime drift."""
        if self.environment != APPROVED_ENVIRONMENT:
            raise ContractError("resource expiry input environment is not approved")
        prepared_at = parse_utc_timestamp(self.prepared_at, "plan preparation time")
        if self.resource_expires_at != generated_resource_expires_at(prepared_at):
            raise ContractError("resource expiry input is not deterministically generated")
        validate_sha256(self.sha256)


@dataclass(frozen=True)
class PlanIdentity:
    """Every governed identity bound to a saved Terraform plan."""

    schema_version: str
    task_id: str
    lifecycle_cycle_id: str
    repository_head: str
    source_composition_sha256: str
    terraform_root: str
    terraform_version: str
    provider_lock_sha256: str
    backend_config_sha256: str
    input_sha256: str
    resource_expiry_input_sha256: str
    resource_expires_at: str
    state_lineage: str | None
    state_serial: int | None
    aws_account_id: str
    aws_region: str
    environment: str
    saved_plan_sha256: str
    plan_json_sha256: str
    policy_result_sha256: str
    cost_result_sha256: str
    created_at: str
    expires_at: str
    approval_id: str | None = None
    approver: str | None = None
    approved_at: str | None = None

    def validate(self) -> None:
        """Reject malformed, incomplete, or overlong identity records."""
        if self.schema_version != LIFECYCLE_SCHEMA_VERSION:
            raise ContractError("plan identity schema_version is not approved")
        if self.task_id != TASK_ID or self.lifecycle_cycle_id != LIFECYCLE_CYCLE_ID:
            raise ContractError("plan identity task or lifecycle cycle is not approved")
        if self.terraform_version != "1.16.1":
            raise ContractError("Terraform version must be exactly 1.16.1")
        if _COMMIT_PATTERN.fullmatch(self.repository_head) is None:
            raise ContractError("repository HEAD must be 40 lowercase hexadecimal characters")
        validate_aws_account_id(self.aws_account_id)
        validate_aws_region(self.aws_region)
        validate_runtime_token(self.environment, "environment")
        if (
            self.aws_account_id != APPROVED_AWS_ACCOUNT_ID
            or self.aws_region != APPROVED_AWS_REGION
            or self.environment != APPROVED_ENVIRONMENT
        ):
            raise ContractError("plan AWS account, Region, or environment is not approved")
        if self.terraform_root not in {
            "infra/bootstrap",
            "infra/environments/sandbox",
        }:
            raise ContractError("Terraform root is not approved")
        for digest in (
            self.source_composition_sha256,
            self.provider_lock_sha256,
            self.backend_config_sha256,
            self.input_sha256,
            self.resource_expiry_input_sha256,
            self.saved_plan_sha256,
            self.plan_json_sha256,
            self.policy_result_sha256,
            self.cost_result_sha256,
        ):
            validate_sha256(digest)
        created_at = parse_utc_timestamp(self.created_at, "plan created_at")
        expires_at = parse_utc_timestamp(self.expires_at, "plan expires_at")
        if self.resource_expires_at != generated_resource_expires_at(created_at):
            raise ContractError("plan resource expiry is not deterministically generated")
        if expires_at <= created_at:
            raise ContractError("plan expiry must follow creation")
        if (expires_at - created_at).total_seconds() > 3600:
            raise ContractError("plan lifetime exceeds 60 minutes")
        if self.state_serial is not None and self.state_serial < 0:
            raise ContractError("state serial cannot be negative")
        if (self.state_lineage is None) != (self.state_serial is None):
            raise ContractError("state lineage and serial must be supplied together")
        approval_fields = (self.approval_id, self.approver, self.approved_at)
        if any(value is not None for value in approval_fields):
            if any(value is None for value in approval_fields):
                raise ContractError("plan approval fields must be supplied together")
            if self.approver != "Gyan-Prakash-Rai":
                raise ContractError("plan approver is not authorized")
            approval_id = self.approval_id
            approved_at_text = self.approved_at
            if approval_id is None or approved_at_text is None:
                raise ContractError("plan approval fields must be supplied together")
            validate_runtime_token(approval_id, "approval_id")
            approved_at = parse_utc_timestamp(approved_at_text, "plan approved_at")
            if approved_at < created_at or approved_at >= expires_at:
                raise ContractError("plan approval timestamp is outside the plan lifetime")


@dataclass(frozen=True)
class PolicyFinding:
    """Redacted deterministic policy result."""

    policy_id: str
    severity: str
    resource_address: str
    remediation_code: str


@dataclass(frozen=True)
class PolicyResult:
    """Real-plan policy evaluation result."""

    status: Outcome
    findings: tuple[PolicyFinding, ...]
    input_sha256: str
    tool: ToolIdentity


@dataclass(frozen=True)
class CostComponent:
    """One estimated monthly cost component."""

    name: str
    monthly_cost: Decimal | None
    usage_based: bool


@dataclass(frozen=True)
class CostResult:
    """Bounded cost decision; incomplete estimates remain indeterminate."""

    status: Outcome
    currency: str
    estimated_monthly_cost: Decimal | None
    estimated_lifecycle_cost: Decimal | None
    monthly_ceiling: Decimal
    lifecycle_ceiling: Decimal
    components: tuple[CostComponent, ...]
    source_sha256: str
    tool: ToolIdentity


@dataclass(frozen=True)
class ResourceRecord:
    """Sanitized state/native-inventory resource identity."""

    service: str
    resource_id: str
    account_id: str
    region: str
    state: ResourceDisposition
    cost_bearing: bool
    tags: tuple[tuple[str, str], ...]
    scheduled_deletion_at: str | None = None


@dataclass(frozen=True)
class CleanupResult:
    """Native and tag-based cleanliness proof."""

    status: Outcome
    resources: tuple[ResourceRecord, ...]
    retained: tuple[ResourceRecord, ...]
    checked_services: tuple[str, ...]
    checked_at: str


@dataclass(frozen=True)
class DeploymentResult:
    """Exact-plan apply result without implying application readiness."""

    status: Outcome
    plan_sha256: str
    applied_at: str | None
    resource_ids: tuple[str, ...]


@dataclass(frozen=True)
class RollbackResult:
    """Infrastructure rollback result, distinct from release rollback."""

    status: Outcome
    last_known_good_plan_sha256: str | None
    rollback_plan_sha256: str | None
    completed_at: str | None


@dataclass(frozen=True)
class DestroyPlanResult:
    """Reviewed destroy-plan identity and exact target inventory."""

    status: Outcome
    saved_plan_sha256: str
    targets: tuple[str, ...]
    bootstrap_included: bool


@dataclass(frozen=True)
class OperationLock:
    """Mutual-exclusion record for one owner-approved lifecycle operation."""

    schema_version: str
    operation_id: str
    action: str
    environment: str
    target: str
    artifact_sha256: str
    created_at: str
    expires_at: str


# Version-one records above describe historical evidence, not execution authority.
OPERATIONAL_SCHEMA_VERSION = "w5-004.lifecycle.v2"
PURGE_INVENTORY_V3_SCHEMA_VERSION = "platformctl.purge-inventory.v3"
W12_PURGE_INVENTORY_SCHEMA_VERSION = "platformctl.purge-inventory.v3"
CONTENT_SCOPE_VERSION = "w5-004.lifecycle-content.v1"


class OperationPhase(StrEnum):
    """Durable states; completion does not imply independent verification."""

    PREPARED = "PREPARED"
    REVIEW_FAILED = "REVIEW_FAILED"
    ELIGIBLE_FOR_REVIEW = "ELIGIBLE_FOR_REVIEW"
    APPROVED = "APPROVED"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_OUTCOME_UNCERTAIN = "EXECUTION_OUTCOME_UNCERTAIN"
    EXECUTION_COMPLETED = "EXECUTION_COMPLETED"
    POST_EXECUTION_VERIFIED = "POST_EXECUTION_VERIFIED"


class ChangeProfile(StrEnum):
    """Action-specific review semantics, never inferred from an artifact name."""

    INITIAL = "INITIAL"
    PARTIAL_RECOVERY = "PARTIAL_RECOVERY"
    ROLLBACK = "ROLLBACK"
    DESTROY = "DESTROY"
    PURGE = "PURGE"


class CoverageClass(StrEnum):
    """Resource-level pricing coverage; a missing price is not zero."""

    PRICED_FIXED = "PRICED_FIXED"
    PRICED_USAGE_WITH_APPROVED_ASSUMPTIONS = "PRICED_USAGE_WITH_APPROVED_ASSUMPTIONS"
    NON_BILLABLE_VERIFIED = "NON_BILLABLE_VERIFIED"
    UNSUPPORTED = "UNSUPPORTED"
    NO_PRICE = "NO_PRICE"
    USAGE_UNBOUNDED = "USAGE_UNBOUNDED"
    ERROR = "ERROR"


@dataclass(frozen=True)
class EvidenceRef:
    """Exclusive operation-relative artifact identity and validity interval."""

    kind: str
    path: str
    sha256: str
    byte_count: int
    producer: str
    created_at: str
    valid_until: str
    operation_id: str


@dataclass(frozen=True)
class IdentityBundle:
    """Independent content, index, authorization and protected-source identities."""

    scope_version: str
    working_sha256: str
    index_sha256: str
    authorization_sha256: str
    governance_sha256: str
    repository_head: str
    tools: tuple[tuple[str, str, str, str], ...]
    inputs: tuple[tuple[str, str], ...]
    backend_sha256: str


@dataclass(frozen=True)
class StateEvidence:
    """Current backend observation; never exposes state attributes or outputs."""

    backend: str
    lineage: str | None
    serial: int | None
    sha256: str
    observed_at: str
    remote_version: str | None
    inventory: EvidenceRef


@dataclass(frozen=True)
class ResourceChangeRule:
    """Explicit action order and semantic deltas for one reviewed address."""

    address: str
    resource_type: str
    actions: tuple[str, ...]
    update_paths: tuple[str, ...]
    delta_rule: str


@dataclass(frozen=True)
class RecoveryProfile:
    """Fresh, enumerated operation boundary, not a historical resource allowlist."""

    profile: ChangeProfile
    action: Action
    rules: tuple[ResourceChangeRule, ...]
    evidence: tuple[EvidenceRef, ...]
    expires_at: str
    service_role_treatment: str
    log_policy_resolution: str
    last_known_good: EvidenceRef | None
    platform_cleanliness: EvidenceRef | None
    cleanup_spending: EvidenceRef | None


@dataclass(frozen=True)
class CostCoverage:
    """One desired-state address, charging model and explicitly bounded exposure."""

    address: str
    scope: str
    classification: CoverageClass
    monthly_usd: str | None
    remaining_usd: str | None
    charging_model: str
    units: str
    duration_seconds: int
    basis: EvidenceRef | None


@dataclass(frozen=True)
class CostResultV2:
    """Whole-platform exposure including previously incurred and retained costs."""

    schema_version: str
    status: Outcome
    currency: str
    saved_plan_sha256: str
    raw_estimate: EvidenceRef
    coverage: tuple[CostCoverage, ...]
    assumptions: tuple[EvidenceRef, ...]
    incurred_usd: str | None
    recovery_usd: str | None
    teardown_retention_usd: str | None
    headroom_usd: str | None
    observed_at: str
    valid_until: str
    billing_observed_at: str | None
    billing_lag_seconds: int | None
    monthly_amendment: EvidenceRef | None = None
    lifecycle_amendment: EvidenceRef | None = None


@dataclass(frozen=True)
class InventoryEntry:
    """Sanitized state/native correspondence with explicit uncertainty."""

    address: str
    resource_type: str
    native_identity: str | None
    state_identity: str | None
    ownership: str
    presence: str
    configuration: Outcome
    cost_bearing: bool | None
    observed_at: str
    scheduled_deletion_at: str | None = None


@dataclass(frozen=True)
class InventoryResult:
    """Complete bounded discovery, including denied and uncovered services."""

    schema_version: str
    operation_id: str
    account_id: str
    region: str
    entries: tuple[InventoryEntry, ...]
    covered_services: tuple[str, ...]
    incomplete_services: tuple[str, ...]
    observed_at: str
    valid_until: str


@dataclass(frozen=True)
class ReviewPackage:
    """Immutable review input to every supported mutation entry point."""

    schema_version: str
    operation_id: str
    action: Action
    target: str
    environment: str
    account_id: str
    region: str
    caller: str
    profile: RecoveryProfile
    identities: IdentityBundle
    artifact: EvidenceRef
    state: StateEvidence
    native: InventoryResult
    policy: EvidenceRef
    cost: CostResultV2
    summary: tuple[ResourceChangeRule, ...]
    prepared_at: str
    resource_expires_at: str
    expires_at: str
    eligibility: Outcome


@dataclass(frozen=True)
class ApprovalRecordV2:
    """Explicit package- and action-bound owner authorization."""

    schema_version: str
    approval_id: str
    approver: str
    executor: str
    action: Action
    profile: ChangeProfile
    account_id: str
    region: str
    environment: str
    target: str
    review_sha256: str
    artifact_kind: str
    artifact_sha256: str
    approved_at: str
    expires_at: str
    confirmation: str


@dataclass(frozen=True)
class OperationResultV2:
    """Safe durable outcome; ambiguous dispatch is never reported as successful."""

    schema_version: str
    operation_id: str
    phase: str
    state: OperationPhase
    classification: Outcome
    exit_code: int
    reason_code: str
    mutation_started: bool
    verification: Outcome
    cleanup: Outcome
    references: tuple[EvidenceRef, ...]


@dataclass(frozen=True)
class DispatchObservation:
    """Fresh observations obtained by the coordinator, not eligibility assertions."""

    identities: IdentityBundle
    state: StateEvidence
    native: InventoryResult
    account_id: str
    region: str
    caller: str
    identity_observed_at: str


@dataclass(frozen=True)
class ReviewRequest:
    """Bounded owner request; no executable Python, expressions or callbacks in JSON."""

    schema_version: str
    operation_id: str
    action: Action
    target: str
    environment: str
    approved_identities: IdentityBundle
    profile: RecoveryProfile
    variables_path: str
    variables_sha256: str
    backend_path: str
    backend_sha256: str
    operation_root: str


@dataclass(frozen=True)
class MutationEnvelope:
    """CLI request binding a package and owner approval to one operation root."""

    schema_version: str
    operation_root: str
    review_path: str
    review_sha256: str
    approval_path: str
    approval_sha256: str


@dataclass(frozen=True)
class CostBoundV2:
    """Separate owner acceptance of a conservative whole-lifecycle upper bound."""

    schema_version: str
    operation_id: str
    action: Action
    artifact_sha256: str
    account_id: str
    currency: str
    scope: str
    lifecycle_upper_usd: str
    monthly_upper_usd: str
    covered_addresses: tuple[str, ...]
    approver: str
    approved_at: str
    expires_at: str
    basis: EvidenceRef


@dataclass(frozen=True)
class PurgeItem:
    """Exact S3 identity; keys and version/upload IDs are not slash-concatenated."""

    kind: str
    key: str
    identifier: str


@dataclass(frozen=True)
class PurgeInventoryV2:
    """Purge authorization artifact, deliberately not a synthetic Terraform plan."""

    schema_version: str
    operation_id: str
    account_id: str
    region: str
    environment: str
    bucket: str
    ownership: str
    items: tuple[PurgeItem, ...]
    retained: tuple[PurgeItem, ...]
    pagination_evidence: EvidenceRef
    observed_at: str
    valid_until: str


@dataclass(frozen=True)
class W12PublishedObject:
    """Exact provider-returned identity, never a latest-version selector."""

    bucket: str
    key: str
    version_id: str
    sha256: str
    last_modified_utc: str


@dataclass(frozen=True)
class W12ProtectedObject:
    bucket: str
    key: str
    version_id: str
    sha256: str
    evidence_kind: str
    coverage: str


@dataclass(frozen=True)
class W12RetentionBinding:
    record_id: str
    operation: str
    verified_record_sha256: str
    verified_created_at_utc: str
    verified_record_object: W12PublishedObject
    verified_sidecar_object: W12PublishedObject
    publication_anchor_utc: str
    retain_until_utc: str
    kms_key_arn: str
    protected_objects: tuple[W12ProtectedObject, ...]


@dataclass(frozen=True)
class PurgeInventoryV3:
    """V2 fields in their reviewed order, followed by path-free W12 proof."""

    schema_version: str
    operation_id: str
    account_id: str
    region: str
    environment: str
    bucket: str
    ownership: str
    items: tuple[PurgeItem, ...]
    retained: tuple[PurgeItem, ...]
    pagination_evidence: EvidenceRef
    observed_at: str
    valid_until: str
    w12_retention_bindings: tuple[W12RetentionBinding, ...]


@dataclass(frozen=True)
class W12RuntimeProofRoots:
    """Invocation-local paths; never serialize into operational evidence."""

    paths: tuple[Path, ...]


@dataclass(frozen=True)
class ChargingComponent:
    """Owner-reviewed units and billing quantum, matched to an actual price component."""

    name: str
    unit: str
    price_usd: str
    monthly_quantity: str
    quantity_per_period: str
    period_seconds: int
    minimum_periods: int


@dataclass(frozen=True)
class ChargingBasis:
    """A resource-specific charging rule; no universal month-to-hour conversion."""

    schema_version: str
    operation_id: str
    address: str
    scope: str
    classification: CoverageClass
    window_start: str
    window_end: str
    components: tuple[ChargingComponent, ...]
    approver: str
    approved_at: str
    expires_at: str
    authority: EvidenceRef


@dataclass(frozen=True)
class PostExecutionRequest:
    """Separate read-only verification request bound to the completed operation."""

    schema_version: str
    operation_root: str
    review_path: str
    review_sha256: str
    state: StateEvidence | None
    native: InventoryResult | None
    evidence: tuple[EvidenceRef, ...]


@dataclass(frozen=True)
class RetentionDecision:
    """Explicit state/audit retention and KMS treatment before bootstrap removal."""

    schema_version: str
    operation_id: str
    account_id: str
    region: str
    environment: str
    state_sha256: str
    retained_artifacts: tuple[EvidenceRef, ...]
    kms_addresses: tuple[str, ...]
    kms_window_days: int
    follow_up_owner: str
    approver: str
    approved_at: str
    expires_at: str


@dataclass(frozen=True)
class KmsRetentionObservation:
    """Original scheduling evidence paired with the independently observed deadline."""

    schema_version: str
    operation_id: str
    address: str
    account_id: str
    region: str
    key_identity: str
    scheduling_approval_id: str
    scheduled_at: str
    deletion_at: str
    native_deletion_at: str
    window_days: int
    observed_at: str
    follow_up_owner: str


@dataclass(frozen=True)
class NativePrerequisiteEvidence:
    """Reviewed external-role or state/native policy disposition, re-read before dispatch."""

    schema_version: str
    operation_id: str
    kind: str
    account_id: str
    region: str
    address: str
    resource_type: str
    native_identity: str
    ownership: str
    presence: str
    state_presence: str
    state_sha256: str
    probe_json: str
    expected_fields_json: str
    observed_at: str
    valid_until: str


@dataclass(frozen=True)
class LastKnownGoodEvidence:
    """A separately approved, independently verified deployment, never a candidate."""

    schema_version: str
    operation_id: str
    deployment_id: str
    source_sha256: str
    account_id: str
    region: str
    environment: str
    approver: str
    approved_at: str
    verification: EvidenceRef


@dataclass(frozen=True)
class CostReviewTerms:
    """Pre-estimate owner assumptions without a guessed future output digest."""

    schema_version: str
    operation_id: str
    scope: str
    coverage: tuple[CostCoverage, ...]
    assumptions: tuple[EvidenceRef, ...]
    incurred_usd: str | None
    recovery_usd: str | None
    teardown_retention_usd: str | None
    billing_observed_at: str | None
    billing_lag_seconds: int | None
    valid_until: str
    monthly_amendment: EvidenceRef | None = None
    lifecycle_amendment: EvidenceRef | None = None


@dataclass(frozen=True)
class MonthlyAmendmentAuthority:
    """Short-lived owner attestation, bound to one operation and current cycle."""

    schema_version: str
    operation_id: str
    amendment_id: str
    cycle_id: str
    account_id: str
    region: str
    environment: str
    bootstrap_lineage: str
    platform_lineage: str
    configuration_sha256: str
    configuration_snapshot: str
    approver: str
    approved_at: str
    valid_until: str
    cycle_status: str


@dataclass(frozen=True)
class LifecycleBudgetAuthority(MonthlyAmendmentAuthority):
    """Operation-bound total-cycle authority, never an incremental spending allowance."""

    lifecycle_ceiling_usd: str
    accounting_scope: str


@dataclass(frozen=True)
class RuntimeConfiguration:
    """Exact external production wiring; never accepts executable callbacks or code."""

    schema_version: str
    tools: tuple[tuple[str, str, str, str], ...]
    child_environment: tuple[tuple[str, str], ...]
    protected_files: tuple[tuple[str, str], ...]
    authorized_status: tuple[tuple[str, str, str | None], ...]
    input_files: tuple[tuple[str, str, str], ...]
    terraform_data_root: str
    native_targets_json: str
    post_execution_targets_json: str
    native_scans_json: str
    cost_terms: CostReviewTerms
    evidence_sources: tuple[tuple[EvidenceRef, str], ...]
    expected_state_lineage: str | None
    expected_state_serial: int | None
    state_probe_json: str | None
    local_state_path: str | None
    preserved_expiry_path: str | None


@dataclass(frozen=True)
class PricingAuthority:
    """Dated owner-reviewed resource price semantics, not an untyped evidence blob."""

    schema_version: str
    operation_id: str
    account_id: str
    region: str
    scope: str
    address: str
    currency: str
    classification: CoverageClass
    components: tuple[ChargingComponent, ...]
    non_billable_reason: str | None
    source_url: str
    source_sha256: str
    observed_at: str
    expires_at: str
    approver: str


@dataclass(frozen=True)
class ExposureComponent:
    """Non-overlapping incurred, incremental and retention accounting intervals."""

    scope: str
    address: str
    category: str
    start: str
    end: str
    amount_usd: str
    source: EvidenceRef


@dataclass(frozen=True)
class ExposureBasis:
    schema_version: str
    operation_id: str
    account_id: str
    currency: str
    components: tuple[ExposureComponent, ...]
    zero_categories: tuple[str, ...]
    billing_observed_at: str
    billing_lag_seconds: int
    approver: str
    approved_at: str
    expires_at: str


@dataclass(frozen=True)
class ExistingReviewRequest:
    schema_version: str
    operation_root: str
    review_path: str
    review_sha256: str


@dataclass(frozen=True)
class FinalizeCostRequest:
    schema_version: str
    operation_root: str
    review_path: str
    review_sha256: str
    conservative_bound: EvidenceRef | None
    evidence_sources: tuple[tuple[EvidenceRef, str], ...]
    reconciled_cost: CostResultV2 | None = None


@dataclass(frozen=True)
class PurgeReviewRequest:
    schema_version: str
    operation_root: str
    request: ReviewRequest
    inventory: PurgeInventoryV2 | PurgeInventoryV3
    cost: CostResultV2


DIAGNOSTIC_SCHEMA_VERSION = "w5-004.prerequisite-diagnostic.v1"


class DiagnosticStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - diagnostic classification, not a credential
    FAIL = "FAIL"
    INDETERMINATE = "INDETERMINATE"
    BLOCKED = "BLOCKED_DEPENDENCY"
    NOT_RUN = "NOT_RUN"


@dataclass(frozen=True)
class DiagnosticCheck:
    check_id: str
    status: DiagnosticStatus
    mandatory: bool
    reason_code: str
    dependencies: tuple[str, ...]
    observed_at: str
    details: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class DiagnosticRequest:
    """Read-only authority cannot decode as any operational request or approval."""

    schema_version: str
    operation_id: str
    environment: str
    target: str
    operation_root: str
    backend_path: str
    backend_sha256: str
    approved_identities: IdentityBundle
    expected_states: tuple[tuple[str, str, int, str], ...]


@dataclass(frozen=True)
class DiagnosticExposureTerms:
    """Owner-reviewed accounting evidence, not asserted incurred dollars."""

    schema_version: str
    operation_id: str
    state_sha256: str
    bootstrap_state_sha256: str
    reviewed_cost: CostResultV2
    query_cost_basis: EvidenceRef


@dataclass(frozen=True)
class DiagnosticQueryCostBasis:
    schema_version: str
    operation_id: str
    account_id: str
    unit_price_usd: str
    maximum_requests: int
    source: EvidenceRef
    source_url: str
    approver: str
    approved_at: str
    valid_until: str


@dataclass(frozen=True)
class DiagnosticFailureResolution:
    schema_version: str
    operation_id: str
    account_id: str
    region: str
    platform_state_sha256: str
    historical_diagnostic_sha256: str
    treatment: str
    approver: str
    approved_at: str
    valid_until: str


@dataclass(frozen=True)
class ResolutionLedgerEntry:
    """Diagnostic accounting; an unknown bound is never zero or approval."""

    category: str
    start: str | None
    end: str | None
    scope: str
    source: str
    observed_usd: str | None
    upper_bound_usd: str | None
    limitation: str


@dataclass(frozen=True)
class PrerequisiteTerms:
    """Approved cycle constraints, not a signature, fresh timestamp or mutation approval."""

    cycle: str = "W5-CYCLE-A"
    account_id: str = "526338061652"
    region: str = "ap-southeast-1"
    bootstrap_lineage: str = "c446f9a2-77d4-9954-20fa-523205d86a8a"
    bootstrap_serial: int = 17
    retention_classification: str = "EXPIRED_EXPLICITLY_RETAINED"
    retention_deadline: str = "2026-09-15T05:15:00Z"
    cleanup_owner: str = "Gyan Prakash Rai"
    operating_seconds: int = 14400
    deployment_seconds: int = 7200
    teardown_start_seconds: int = 10800
    resource_expiry_seconds: int = 85500
    s3_objects: int = 10
    s3_object_bytes: int = 10485760
    s3_total_version_bytes: int = 104857600
    s3_put_requests: int = 10
    s3_get_requests: int = 10
    s3_head_requests: int = 10
    s3_list_requests: int = 2
    ecr_images: int = 1
    ecr_tags: int = 1
    ecr_layers: int = 10
    ecr_total_bytes: int = 104857600
    ecr_pushes: int = 1
    ecr_pulls: int = 1
    ecr_requests: int = 64
    log_ingestion_bytes: int = 104857600
    endpoint_processing_bytes: int = 1073741824
    load_generation: bool = False
    s3_overwrites_or_multipart: bool = False
    destruction_authorized: bool = False
    retained_tail_disposition: str = "UNRESOLVED_REQUIRES_SEPARATE_DISPOSITION"


@dataclass(frozen=True)
class CycleCostBoundBasis:
    schema_version: str
    cycle: str
    currency: str
    entries: tuple[ResolutionLedgerEntry, ...]
    sources: tuple[EvidenceRef, ...]
    retained_terminal_disposition: EvidenceRef
    charging_minima_verified: bool
    billing_lag_bounded: bool
    observed_at: str
    charging_evidence: EvidenceRef | None = None


@dataclass(frozen=True)
class RecoveryScopeDeclaration:
    cycle: str
    account_id: str
    resources: tuple[str, ...]
    intent: str
    approval_path: str
    approval_sha256: str
    ownership_certified: bool = False


@dataclass(frozen=True)
class CycleCharge:
    """A charging component, not an arbitrary asserted category total."""

    component_id: str
    resource: str
    charge_basis: str
    category: str
    start: str
    end: str | None
    unit: str
    quantity: str | None
    rate_usd: str | None
    quantum: str | None
    minimum: str | None
    rate_source: EvidenceRef | None
    quantity_source: EvidenceRef | None
    allowance: bool = False


@dataclass(frozen=True)
class CycleChargingEvidence:
    schema_version: str
    cycle: str
    currency: str
    components: tuple[CycleCharge, ...]
    required_components: tuple[str, ...]
    observed_at: str
    terminal_disposition: EvidenceRef | None
    sources: tuple[tuple[EvidenceRef, str], ...] = ()


@dataclass(frozen=True)
class ResolutionCostLedger:
    schema_version: str
    cycle: str
    currency: str
    total_cycle_ceiling_usd: str
    monthly_treatment: str
    entries: tuple[ResolutionLedgerEntry, ...]
    reported_account_usd: str | None
    attributable_incurred_usd: str | None
    supported_upper_bound_usd: str | None
    available_headroom_usd: str | None
    billing_requests_this_attempt: int
    execution_cost_approval: str = "NOT_ESTABLISHED"


@dataclass(frozen=True)
class DiagnosticRuntimeConfiguration:
    """Shared identity inputs, but no execution adapters, approval or guessed cost."""

    schema_version: str
    tools: tuple[tuple[str, str, str, str], ...]
    child_environment: tuple[tuple[str, str], ...]
    protected_files: tuple[tuple[str, str], ...]
    authorized_status: tuple[tuple[str, str, str | None], ...]
    input_files: tuple[tuple[str, str, str], ...]
    terraform_data_root: str
    bootstrap_backend_path: str
    bootstrap_backend_sha256: str
    native_targets_json: str
    bootstrap_targets_json: str
    native_scans_json: str
    platform_rules: tuple[ResourceChangeRule, ...]
    bootstrap_rules: tuple[ResourceChangeRule, ...]
    retained_pricing: tuple[EvidenceRef, str] | None
    exposure: DiagnosticExposureTerms | None
    evidence_sources: tuple[tuple[EvidenceRef, str], ...]
    failure_resolution: EvidenceRef | None


@dataclass(frozen=True)
class DiagnosticReport:
    schema_version: str
    operation_id: str
    account_id: str
    region: str
    started_at: str
    completed_at: str
    checks: tuple[DiagnosticCheck, ...]
    exit_code: int
    request_sha256: str
    runtime_sha256: str
    aws_requests: int
    billing_requests: int
    recovery_eligibility: str = "NOT_ESTABLISHED"
    mutation_started: bool = False


class W6004Stage(StrEnum):
    BOOTSTRAP_STATE = "bootstrap_state"
    NETWORK_SECURITY = "network_security"
    DATA_SERVICES = "data_services"
    ECR_IMAGE = "ecr_image"
    EKS_IDENTITY = "eks_identity"
    APPLICATION_COMPOSITION = "application_composition"
    OBSERVABILITY = "observability"
    LIVE_TESTS = "live_tests"
    ROLLBACK = "rollback"
    COMPLETE_TEARDOWN = "complete_teardown"
    RESIDUE_COST_VERIFICATION = "residue_cost_verification"


class W6004EvidenceStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - evidence status, not a credential
    FAIL = "FAIL"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class W6004StageEvidence:
    schema_version: str
    operation_id: str
    stage: W6004Stage
    status: W6004EvidenceStatus
    source_sha256: str
    artifact_sha256: str
    started_at: str
    completed_at: str
    warnings: tuple[str, ...] = ()
    residuals: tuple[str, ...] = ()


# W7-001 additive hardening contracts. Historical W5/W6 schemas remain unchanged.
W7_001_SCHEMA_VERSION = "w7-001.remediation.v1"


class EvidenceDisposition(StrEnum):
    CURRENT = "CURRENT"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    SUPERSEDED = "SUPERSEDED"
    WAIVED = "WAIVED"
    LIMITED = "LIMITED"
    CLOSURE_TAIL = "CLOSURE_TAIL"


class EvidenceLifecycle(StrEnum):
    ACTIVE = "ACTIVE"
    CONSUMED = "CONSUMED"
    EXPIRED = "EXPIRED"


class ResidueLocation(StrEnum):
    REPOSITORY = "REPOSITORY"
    EXTERNAL = "EXTERNAL"


class ResidueStatus(StrEnum):
    ABSENT = "ABSENT"
    RETAINED = "RETAINED"
    UNEXPECTED = "UNEXPECTED"


class ControlResult(StrEnum):
    PASS = "PASS"  # noqa: S105 - evidence classification, not a credential.
    FAIL = "FAIL"
    NO_DATA = "NO_DATA"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


@dataclass(frozen=True)
class TemporaryIamOperation:
    schema_version: str
    operation_id: str
    principal: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    conditions: tuple[tuple[str, str], ...]
    source_sha256: str
    approval_id: str
    issued_at: str
    expires_at: str
    operation_expires_at: str
    before_state_sha256: str
    after_state_sha256: str | None
    restoration_status: ControlResult
    partial_failure_cleanup: ControlResult


@dataclass(frozen=True)
class BedrockLoggingContract:
    schema_version: str
    enabled: bool
    synthetic_only: bool
    account_id: str
    region: str
    approval_id: str | None
    operation_id: str | None
    retention_days: int
    encryption_identity: str
    access_identity_sha256: str
    before_state_sha256: str
    after_state_sha256: str | None
    disablement_status: ControlResult
    raw_protected_content_allowed: bool = False


@dataclass(frozen=True)
class RecoverySnapshotContract:
    schema_version: str
    operation_id: str
    external_path: str
    state_lineage: str
    state_serial: int
    content_sha256: str
    encryption_identity: str
    recovery_principal: str
    retention_until: str
    cleanup_owner: str
    plaintext_retained: bool
    mutation_allowed: bool
    rehearsal_status: ControlResult


@dataclass(frozen=True)
class ControlMatrixRow:
    control_id: str
    mandatory: bool
    executor: str
    mutation_type: str
    expected_result: str
    evidence: EvidenceRef | None
    dependency_ids: tuple[str, ...]
    result: ControlResult


@dataclass(frozen=True)
class EvidenceIndexRecord:
    record_id: str
    disposition: EvidenceDisposition
    lifecycle: EvidenceLifecycle
    source_sha256: str
    configuration_sha256: str
    tool_sha256: str
    artifact: EvidenceRef
    reviewer: str | None
    approval_id: str | None
    retained_until: str
    cleanup_owner: str
    supersedes: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProductionReadinessReference:
    schema_version: str
    review_sha256: str
    reviewer: str
    decision: str | None
    decided_at: str | None


@dataclass(frozen=True)
class ResidueClassification:
    path: str
    location: ResidueLocation
    status: ResidueStatus
    expected: bool
    cleanup_owner: str
