"""Separately owner-gated purge, platform-destroy, and bootstrap-destroy validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from .contracts import (
    Action,
    ApprovalConsumptionRegistry,
    ApprovalRecord,
    ApprovalUsageRegistry,
    ContractError,
    ExitCode,
    MutationRequest,
    OperationResult,
    VerifiedExecutionContext,
    parse_utc_timestamp,
    validate_mutation_request,
)
from .lifecycle_io import canonical_json_bytes, decode_operational_record, sha256_bytes
from .lifecycle_models import (
    OPERATIONAL_SCHEMA_VERSION,
    OperationPhase,
    PurgeInventoryV2,
    PurgeItem,
)
from .operation_state import OperationLedger
from .terraform_runner import TerraformRunner

if TYPE_CHECKING:
    from .contracts import EvidenceReader
    from .lifecycle_models import InventoryResult, OperationResultV2, ReviewPackage, StateEvidence


def validate_purge_review(
    package: ReviewPackage,
    reader: EvidenceReader,
    now: datetime,
) -> PurgeInventoryV2:
    """Purge policy is exact inventory reconciliation, not create-only Terraform policy."""
    from .lifecycle_io import decode_json_strict

    inventory = decode_operational_record(
        reader.read(package.artifact.path, package.artifact.sha256, package.artifact.byte_count),
        PurgeInventoryV2,
    )
    if (
        inventory.operation_id != package.operation_id
        or inventory.account_id != package.account_id
        or inventory.region != package.region
        or inventory.environment != package.environment
        or inventory.ownership != "PROJECT_MANAGED"
        or not inventory.bucket
        or not inventory.items
        or len(package.native.entries) != 1
        or package.native.entries[0].native_identity != inventory.bucket
        or package.native.entries[0].presence != "PRESENT"
        or not 0
        <= (now - parse_utc_timestamp(inventory.observed_at, "purge observation")).total_seconds()
        <= 900
    ):
        raise ContractError("PURGE_REVIEW_TARGET_OR_FRESHNESS")
    all_items = (*inventory.items, *inventory.retained)
    if len(set(all_items)) != len(all_items) or any(
        item.kind not in {"OBJECT_VERSION", "DELETE_MARKER", "MULTIPART_UPLOAD"}
        or not item.key
        or not item.identifier
        for item in all_items
    ):
        raise ContractError("PURGE_REVIEW_ITEM_OR_RETENTION")
    for items in (inventory.items, inventory.retained):
        if tuple(sorted(items, key=lambda item: (item.kind, item.key, item.identifier))) != items:
            raise ContractError("PURGE_REVIEW_ORDER")
    ref = inventory.pagination_evidence
    proof = decode_json_strict(reader.read(ref.path, ref.sha256, ref.byte_count))
    if (
        not isinstance(proof, dict)
        or set(proof)
        != {
            "schema_version",
            "operation_id",
            "bucket",
            "versions_complete",
            "uploads_complete",
            "inventory_sha256",
            "retained_sha256",
            "observed_at",
            "valid_until",
        }
        or (
            proof.get("schema_version") != OPERATIONAL_SCHEMA_VERSION
            or ref.operation_id != package.operation_id
            or proof.get("operation_id") != package.operation_id
            or proof.get("bucket") != inventory.bucket
            or proof.get("versions_complete") is not True
            or proof.get("uploads_complete") is not True
            or proof.get("inventory_sha256") != sha256_bytes(canonical_json_bytes(all_items))
            or proof.get("retained_sha256")
            != sha256_bytes(canonical_json_bytes(inventory.retained))
            or proof.get("observed_at") != inventory.observed_at
            or proof.get("valid_until") != inventory.valid_until
        )
    ):
        raise ContractError("PURGE_PAGINATION_OR_RETENTION_UNPROVEN")
    if package.summary[0].address == "aws_s3_bucket.terraform_state":
        from .contracts import _validate_bootstrap_retention, _validate_platform_cleanliness

        if package.profile.platform_cleanliness is None:
            raise ContractError("STATE_BUCKET_PURGE_PLATFORM_REMOVAL_REQUIRED")
        _validate_platform_cleanliness(package, reader, now)
        _validate_bootstrap_retention(package, reader, now)
    elif package.summary[0].address != "module.storage.aws_s3_bucket.this":
        raise ContractError("PURGE_BUCKET_RESOURCE_NOT_APPROVED")
    return inventory


class PurgeAdapter(Protocol):
    """Exact S3 inventory and one-item mutation boundary, never a broad bucket purge."""

    def inventory(self, expected: PurgeInventoryV2) -> tuple[PurgeItem, ...]:
        """Return complete current versions, markers and uploads, or raise."""
        ...

    def remove(
        self,
        item: PurgeItem,
        *,
        context: VerifiedExecutionContext,
        ledger: OperationLedger,
        sequence: int,
    ) -> None:
        """Delete one exact item only after its durable batch-start marker."""
        ...


def validate_purge_inventory(
    inventory: PurgeInventoryV2, context: VerifiedExecutionContext
) -> None:
    """Validate exact, disjoint purge and retained identities without exposing object keys."""
    package = context.package
    if (
        inventory.schema_version != OPERATIONAL_SCHEMA_VERSION
        or inventory.operation_id != package.operation_id
        or inventory.account_id != package.account_id
        or inventory.region != package.region
        or inventory.environment != package.environment
        or inventory.ownership != "PROJECT_MANAGED"
        or not inventory.bucket
        or not inventory.items
        or parse_utc_timestamp(inventory.valid_until, "purge expiry")
        < parse_utc_timestamp(package.expires_at, "review expiry")
        or sha256_bytes(canonical_json_bytes(inventory)) != package.artifact.sha256
    ):
        raise ContractError("PURGE_INVENTORY_BINDING")
    identities = (*inventory.items, *inventory.retained)
    if len(identities) != len(set(identities)):
        raise ContractError("PURGE_DUPLICATE_OR_RETENTION_OVERLAP")
    for item in identities:
        if item.kind not in {"OBJECT_VERSION", "DELETE_MARKER", "MULTIPART_UPLOAD"} or (
            not item.key or not item.identifier
        ):
            raise ContractError("PURGE_ITEM_IDENTITY_INVALID")
    if (
        tuple(sorted(inventory.items, key=lambda item: (item.kind, item.key, item.identifier)))
        != inventory.items
    ):
        raise ContractError("PURGE_ITEM_ORDER_INVALID")


def purge_approved_inventory(
    context: VerifiedExecutionContext,
    ledger: OperationLedger,
    adapter: PurgeAdapter,
    now: datetime,
) -> OperationResult:
    """Consume once, reconcile each exact batch and stop on any partial outcome."""
    if not isinstance(context, VerifiedExecutionContext) or not isinstance(ledger, OperationLedger):
        raise ContractError("VERIFIED_CONTEXT_AND_LEDGER_REQUIRED")
    package = context.package
    if package.action is not Action.PURGE_SANDBOX or package.artifact.kind != "purge-inventory":
        raise ContractError("PURGE_ACTION_REQUIRED")
    inventory = decode_operational_record(context.artifact_bytes(), PurgeInventoryV2)
    validate_purge_inventory(inventory, context)
    context.revalidate(package.action, package.artifact.sha256, consumed=False)
    expected = set((*inventory.items, *inventory.retained))
    observed_initial = adapter.inventory(inventory)
    if len(observed_initial) != len(set(observed_initial)) or set(observed_initial) != expected:
        raise ContractError("PURGE_PRE_DISPATCH_INVENTORY_DRIFT")
    ledger.begin_execution(context, now)
    phase = OperationPhase.EXECUTION_COMPLETED
    reason = "PURGE_COMPLETED_VERIFICATION_PENDING"
    try:
        for sequence, item in enumerate(inventory.items, start=1):
            context.revalidate(package.action, package.artifact.sha256, consumed=True)
            observed = adapter.inventory(inventory)
            if len(observed) != len(set(observed)) or set(observed) != expected:
                raise ContractError("PURGE_BATCH_INVENTORY_DRIFT")
            ledger.start_purge_batch(context, sequence, item)
            adapter.remove(item, context=context, ledger=ledger, sequence=sequence)
            expected.remove(item)
            remaining = adapter.inventory(inventory)
            if len(remaining) != len(set(remaining)) or set(remaining) != expected:
                raise ContractError("PURGE_BATCH_OUTCOME_UNCERTAIN")
            ledger.complete_purge_batch(context, sequence, item)
    except Exception:
        phase = OperationPhase.EXECUTION_OUTCOME_UNCERTAIN
        reason = "PURGE_STOPPED_RECONCILIATION_REQUIRED"
    try:
        result = ledger.finish_execution(context, phase, reason)
    except ContractError:
        return OperationResult(
            ExitCode.VALIDATION_FAILURE,
            "INDETERMINATE: purge durability failure",
            "PURGE_DURABILITY_UNCERTAIN",
        )
    return OperationResult(ExitCode(result.exit_code), reason, reason)


def verify_purge_execution(
    package: ReviewPackage,
    state: StateEvidence,
    native: InventoryResult,
    *,
    reader: EvidenceReader,
    adapter: PurgeAdapter,
    ledger: OperationLedger,
    now: datetime,
) -> OperationResultV2:
    """Independently reconcile retained versions/uploads; a bucket read is insufficient."""
    from .lifecycle_models import OperationResultV2, Outcome

    history = ledger.journal(package.operation_id)
    if (
        package.action is not Action.PURGE_SANDBOX
        or not history
        or (
            history[-1]["state"] != OperationPhase.EXECUTION_COMPLETED.value
            or history[-1]["artifact_sha256"] != package.artifact.sha256
        )
    ):
        raise ContractError("PURGE_POST_VERIFICATION_PHASE")
    if (state.backend, state.lineage, state.serial, state.sha256, state.remote_version) != (
        package.state.backend,
        package.state.lineage,
        package.state.serial,
        package.state.sha256,
        package.state.remote_version,
    ) or not 0 <= (
        now - parse_utc_timestamp(state.observed_at, "state observation")
    ).total_seconds() <= 60:
        raise ContractError("PURGE_POST_STATE_DRIFT_OR_STALE")
    if (
        native.operation_id != package.operation_id
        or native.account_id != package.account_id
        or (
            native.region != package.region
            or native.incomplete_services
            or not native.covered_services
            or not 0
            <= (now - parse_utc_timestamp(native.observed_at, "native observation")).total_seconds()
            <= 900
            or parse_utc_timestamp(native.valid_until, "native expiry") <= now
            or len(native.entries) != 1
        )
    ):
        raise ContractError("PURGE_POST_NATIVE_INCOMPLETE")
    inventory = decode_operational_record(
        reader.read(package.artifact.path, package.artifact.sha256, package.artifact.byte_count),
        PurgeInventoryV2,
    )
    bucket = native.entries[0]
    if (
        bucket.address != package.summary[0].address
        or bucket.native_identity != inventory.bucket
        or (
            bucket.presence != "PRESENT"
            or bucket.ownership != "PROJECT_MANAGED"
            or bucket.configuration is not Outcome.PASS
        )
    ):
        raise ContractError("PURGE_POST_BUCKET_CHANGED")
    actual = adapter.inventory(inventory)
    if len(actual) != len(set(actual)) or set(actual) != set(inventory.retained):
        raise ContractError("PURGE_POST_RETAINED_INVENTORY_MISMATCH")
    result = OperationResultV2(
        OPERATIONAL_SCHEMA_VERSION,
        package.operation_id,
        "POST_EXECUTION_VERIFICATION",
        OperationPhase.POST_EXECUTION_VERIFIED,
        Outcome.PASS,
        0,
        "PURGE_VERIFIED_WITH_APPROVED_RETENTION" if actual else "PURGE_VERIFIED_BUCKET_RETAINED",
        True,
        Outcome.PASS,
        Outcome.NOT_RUN,
        (package.artifact, state.inventory),
    )
    ledger.record_post_verification(package.operation_id, result, now)
    return result


class DestroyMode(StrEnum):
    """Approved destruction behaviors with different safety semantics."""

    PURGE_SANDBOX = "purge-sandbox"
    PLATFORM_DESTROY = "platform-destroy"
    BOOTSTRAP_DESTROY = "bootstrap-destroy"


@dataclass(frozen=True)
class S3PurgeInventory:
    """Exact versioned-object residue that requires separate purge approval."""

    bucket: str
    object_versions: tuple[str, ...]
    delete_markers: tuple[str, ...]
    multipart_uploads: tuple[str, ...]


def validate_s3_purge_inventory(inventory: S3PurgeInventory) -> None:
    """Reject blank, duplicate, or non-deterministic purge targets."""
    if not inventory.bucket or any(char.isspace() for char in inventory.bucket):
        raise ContractError("S3 purge bucket identity is invalid")
    for name, values in (
        ("object_versions", inventory.object_versions),
        ("delete_markers", inventory.delete_markers),
        ("multipart_uploads", inventory.multipart_uploads),
    ):
        if any(not value for value in values) or tuple(sorted(values)) != values:
            raise ContractError(f"S3 purge {name} must be nonblank and sorted")
        if len(values) != len(set(values)):
            raise ContractError(f"S3 purge {name} contains duplicates")


def action_for_mode(mode: DestroyMode) -> Action:
    """Map a CLI mode to its separately approved action value."""
    if mode is DestroyMode.PURGE_SANDBOX:
        return Action.PURGE_SANDBOX
    if mode is DestroyMode.PLATFORM_DESTROY:
        return Action.PLATFORM_DESTROY
    return Action.BOOTSTRAP_DESTROY


def validate_request(
    mode: DestroyMode,
    request: MutationRequest,
    approval: ApprovalRecord,
    usage_registry: ApprovalUsageRegistry,
    now: datetime,
) -> OperationResult:
    """Validate destruction intent without deleting any resource."""
    expected_action = action_for_mode(mode)
    if request.action is not expected_action:
        raise ContractError("destroy request action does not match its mode")
    if mode is DestroyMode.PURGE_SANDBOX and request.environment != "sandbox":
        raise ContractError("purge-sandbox is permitted only for sandbox")
    if mode is DestroyMode.BOOTSTRAP_DESTROY and request.target != "bootstrap":
        raise ContractError("bootstrap-destroy requires the exact bootstrap target")
    if mode is DestroyMode.PLATFORM_DESTROY and request.target != "platform":
        raise ContractError("platform-destroy requires the exact platform target")
    validate_mutation_request(
        request,
        approval,
        usage_registry,
        now,
    )
    return OperationResult(
        ExitCode.SUCCESS,
        f"DRY_RUN: {mode.value} intent validated; no teardown executed",
    )


def validate_destroy_order(
    completed_targets: tuple[str, ...],
    requested_target: str,
    *,
    platform_clean: bool,
) -> None:
    """Require platform cleanup proof before bootstrap destruction."""
    if requested_target == "bootstrap":
        if not platform_clean or "platform" not in completed_targets:
            raise ContractError("bootstrap destruction requires prior platform cleanliness proof")
    elif requested_target != "platform":
        raise ContractError("destroy target is not approved")


def apply_approved_destroy_plan(
    mode: DestroyMode,
    request: MutationRequest,
    approval: ApprovalRecord,
    usage_registry: ApprovalConsumptionRegistry,
    now: datetime,
    *,
    runner: TerraformRunner,
    terraform_root: Path,
    saved_plan: Path,
    execution_context: VerifiedExecutionContext | None = None,
    completed_targets: tuple[str, ...],
    platform_clean: bool,
) -> OperationResult:
    """Apply exact destroy-plan bytes after mode and bootstrap-last checks."""
    validate_request(mode, request, approval, usage_registry, now)
    validate_destroy_order(
        completed_targets,
        request.target,
        platform_clean=platform_clean,
    )
    from .plan import execute_reviewed_plan

    return execute_reviewed_plan(
        request,
        approval.approval_id,
        usage_registry,
        now,
        runner=runner,
        terraform_root=terraform_root,
        saved_plan=saved_plan,
        execution_context=execution_context,
    )


def validate_w6_004_final_residue(actual: tuple[str, ...]) -> None:
    """Accept only approved asynchronous or external residual classes."""

    from .live_validation import validate_residue

    expected = (
        "final_evidence",
        "shared_external_service_linked_roles",
        "kms_keys_pending_deletion",
        "delayed_billing_records",
    )
    validate_residue(actual, expected)
