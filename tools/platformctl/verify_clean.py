"""Fail-closed cleanup classification over injected inventory interfaces."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from .aws_inventory import (
    AwsInventoryProvider,
    InventoryResource,
    InventoryUnavailable,
    KmsSchedulingEvidence,
    ResourceState,
    ServiceIdentifier,
)
from .contracts import (
    APPROVED_AWS_ACCOUNT_ID,
    APPROVED_AWS_REGION,
    Action,
    ContractError,
    ExitCode,
    OperationResult,
    parse_utc_timestamp,
    stable_cleanup_tags,
    validate_sha256,
)

if TYPE_CHECKING:
    from .contracts import EvidenceReader
    from .lifecycle_models import (
        EvidenceRef,
        InventoryEntry,
        InventoryResult,
        OperationResultV2,
        ReviewPackage,
        StateEvidence,
    )
    from .operation_state import OperationLedger


def _resource_key(resource: InventoryResource) -> tuple[ServiceIdentifier, str]:
    return resource.service, resource.resource_id


def _has_managed_tags(resource: InventoryResource, required_tags: dict[str, str]) -> bool:
    if not resource.resource_id:
        return False
    if any(resource.tags.get(key) != value for key, value in required_tags.items()):
        return False
    resource_expiry = resource.tags.get("ExpiresAt")
    if resource_expiry is None:
        return False
    try:
        parse_utc_timestamp(resource_expiry, "resource ExpiresAt")
    except ContractError:
        return False
    return True


def _is_expected_kms_residual(
    resource: InventoryResource,
    now: datetime,
    scheduling_evidence: tuple[KmsSchedulingEvidence, ...] = (),
) -> bool:
    if resource.service is not ServiceIdentifier.KMS:
        return False
    if resource.state is not ResourceState.PENDING_DELETION:
        return False
    if resource.scheduled_deletion_at is None:
        return False
    try:
        scheduled_at = parse_utc_timestamp(resource.scheduled_deletion_at, "scheduled KMS deletion")
    except ContractError:
        return False
    records = [
        record for record in scheduling_evidence if record.key_identity == resource.resource_id
    ]
    if len(records) != 1:
        return False
    record = records[0]
    try:
        validate_sha256(record.evidence_sha256)
        original = parse_utc_timestamp(record.scheduled_at, "KMS original schedule")
        approved_deletion = parse_utc_timestamp(record.deletion_at, "KMS approved deletion")
    except ContractError:
        return False
    return (
        record.account_id == resource.account_id == APPROVED_AWS_ACCOUNT_ID
        and record.region == resource.region == APPROVED_AWS_REGION
        and record.window_days == 7
        and bool(record.approval_id)
        and approved_deletion == original + timedelta(days=record.window_days)
        and approved_deletion == scheduled_at
        and original <= now < approved_deletion
    )


def verify_clean(
    provider: AwsInventoryProvider,
    environment: str,
    now: datetime,
    *,
    scheduling_evidence: tuple[KmsSchedulingEvidence, ...] = (),
) -> OperationResult:
    """Combine tag and native checks without claiming unavailable inventory."""
    required_tags = stable_cleanup_tags(environment)
    resources: dict[tuple[ServiceIdentifier, str], InventoryResource] = {}

    def record_resource(resource: InventoryResource) -> None:
        key = _resource_key(resource)
        if key in resources and resources[key] != resource:
            raise InventoryUnavailable("native and tag inventories disagree")
        resources[key] = resource

    try:
        for resource in provider.list_tagged_resources(required_tags):
            record_resource(resource)
        for service in ServiceIdentifier:
            for resource in provider.list_service_resources(service):
                record_resource(resource)
    except InventoryUnavailable:
        return OperationResult(
            ExitCode.PROVIDER_UNAVAILABLE,
            "INDETERMINATE: required AWS inventory provider is unavailable",
        )

    unmanaged_count = 0
    active_or_unknown_count = 0
    cost_bearing_count = 0
    expected_kms_count = 0
    for resource in resources.values():
        if resource.owner_classification in {"SHARED", "OWNER_MANAGED", "UNRELATED"}:
            continue
        region_valid = resource.region == APPROVED_AWS_REGION or (
            resource.service is ServiceIdentifier.IAM and resource.region == "global"
        )
        if resource.account_id != APPROVED_AWS_ACCOUNT_ID or not region_valid:
            unmanaged_count += 1
            continue
        managed = _has_managed_tags(resource, required_tags)
        if not managed:
            unmanaged_count += 1
            continue
        if resource.state is ResourceState.ABSENT:
            continue
        if _is_expected_kms_residual(resource, now, scheduling_evidence):
            expected_kms_count += 1
            continue
        active_or_unknown_count += 1
        if resource.cost_bearing:
            cost_bearing_count += 1

    if unmanaged_count or active_or_unknown_count or cost_bearing_count:
        return OperationResult(
            ExitCode.VALIDATION_FAILURE,
            "CLEANLINESS FAIL: "
            f"{unmanaged_count} unmanaged and "
            f"{active_or_unknown_count} active/unknown residual(s), "
            f"including {cost_bearing_count} cost-bearing residual(s)",
        )

    return OperationResult(
        ExitCode.SUCCESS,
        "CLEANLINESS PASS: no active or unmanaged residuals; "
        f"{expected_kms_count} evidenced KMS PendingDeletion residual(s)",
    )


def verify_post_execution(
    package: ReviewPackage,
    state: StateEvidence,
    native: InventoryResult,
    *,
    now: datetime,
    reader: EvidenceReader,
    ledger: OperationLedger,
    retention_evidence: tuple[EvidenceRef, ...] = (),
) -> OperationResultV2:
    """Verify completion from fresh independent observations, never a process exit alone."""
    from .lifecycle_io import decode_json_strict
    from .lifecycle_models import (
        OPERATIONAL_SCHEMA_VERSION,
        OperationPhase,
        OperationResultV2,
        Outcome,
    )

    if package.action is Action.PURGE_SANDBOX:
        raise ContractError("PURGE_REQUIRES_OBJECT_LEVEL_POST_VERIFICATION")

    history = ledger.journal(package.operation_id)
    if not history or history[-1]["state"] != OperationPhase.EXECUTION_COMPLETED.value:
        raise ContractError("POST_VERIFY_EXECUTION_COMPLETION_REQUIRED")
    if history[-1]["artifact_sha256"] != package.artifact.sha256:
        raise ContractError("POST_VERIFY_ARTIFACT_MISMATCH")
    for timestamp, maximum in ((state.observed_at, 60), (native.observed_at, 900)):
        if (
            not 0
            <= (now - parse_utc_timestamp(timestamp, "verification observation")).total_seconds()
            <= maximum
        ):
            raise ContractError("POST_VERIFY_OBSERVATION_STALE")
    if (
        native.operation_id != package.operation_id
        or native.account_id != package.account_id
        or native.region != package.region
        or native.incomplete_services
        or not native.covered_services
        or state.backend != package.state.backend
        or (package.state.lineage is not None and state.lineage != package.state.lineage)
        or state.serial is None
        or type(state.serial) is not int
        or state.serial < (package.state.serial or 0)
        or parse_utc_timestamp(native.valid_until, "native expiry") <= now
    ):
        raise ContractError("POST_VERIFY_STATE_OR_COVERAGE")
    inventory = decode_json_strict(
        reader.read(state.inventory.path, state.inventory.sha256, state.inventory.byte_count)
    )
    if (
        not isinstance(inventory, dict)
        or set(inventory) != {"schema_version", "operation_id", "state_sha256", "managed_resources"}
        or inventory.get("schema_version") != OPERATIONAL_SCHEMA_VERSION
        or (
            inventory.get("operation_id") != package.operation_id
            or inventory.get("state_sha256") != state.sha256
        )
    ):
        raise ContractError("POST_VERIFY_STATE_INVENTORY_BINDING")
    managed = inventory["managed_resources"]
    if not isinstance(managed, list) or any(
        not isinstance(item, dict) or set(item) != {"address", "resource_type"} for item in managed
    ):
        raise ContractError("POST_VERIFY_STATE_INVENTORY_MALFORMED")
    state_pairs = {(item["address"], item["resource_type"]) for item in managed}
    if len(state_pairs) != len(managed):
        raise ContractError("POST_VERIFY_STATE_DUPLICATED")
    observations = {item.address: item for item in native.entries}
    if len(observations) != len(native.entries) or set(observations) != {
        rule.address for rule in package.summary
    }:
        raise ContractError("POST_VERIFY_NATIVE_INVENTORY_NOT_EXACT")
    expected_state: set[tuple[str, str]] = set()
    retained_addresses: set[str] = set()
    for rule in package.summary:
        entry = observations[rule.address]
        if entry.resource_type != rule.resource_type or entry.ownership != "PROJECT_MANAGED":
            raise ContractError("POST_VERIFY_RESOURCE_OWNERSHIP")
        if (
            rule.resource_type == "aws_iam_policy_document"
            and ".data.aws_iam_policy_document." in "." + rule.address
        ):
            if (
                rule.actions not in {("read",), ("no-op",)}
                or entry.presence != "EVALUATION_ONLY"
                or entry.cost_bearing is not False
            ):
                raise ContractError("POST_VERIFY_DATA_SOURCE_CLASSIFICATION")
            continue
        deleted = rule.actions == ("delete",)
        if deleted:
            if entry.resource_type == "aws_kms_key" and entry.presence == "PENDING_DELETION":
                _verify_kms_retention(package, entry, retention_evidence, reader, now)
                scheduling = [
                    reference
                    for reference in retention_evidence
                    if reference.kind == "kms-scheduling-observation"
                ]
                from .lifecycle_io import decode_operational_record
                from .lifecycle_models import KmsRetentionObservation

                for reference in scheduling:
                    record = decode_operational_record(
                        reader.read(reference.path, reference.sha256, reference.byte_count),
                        KmsRetentionObservation,
                    )
                    if (
                        record.address == entry.address
                        and record.scheduling_approval_id != history[-1]["approval_id"]
                    ):
                        raise ContractError("KMS_SCHEDULE_APPROVAL_NOT_CONSUMED_OPERATION")
                retained_addresses.add(entry.address)
            elif entry.presence != "ABSENT" or entry.cost_bearing is not False:
                raise ContractError("POST_VERIFY_RETAINED_OR_UNKNOWN_RESOURCE")
        else:
            if entry.presence != "PRESENT" or entry.configuration is not Outcome.PASS:
                raise ContractError("POST_VERIFY_RESOURCE_NOT_VALIDATED")
            if rule.actions != ("read",):
                expected_state.add((rule.address, rule.resource_type))
    if state_pairs != expected_state:
        raise ContractError("POST_VERIFY_STATE_RESOURCE_MISMATCH")
    result = OperationResultV2(
        OPERATIONAL_SCHEMA_VERSION,
        package.operation_id,
        "POST_EXECUTION_VERIFICATION",
        OperationPhase.POST_EXECUTION_VERIFIED,
        Outcome.PASS,
        0,
        "POST_EXECUTION_VERIFIED_WITH_KMS_RETENTION"
        if retained_addresses
        else "POST_EXECUTION_VERIFIED",
        True,
        Outcome.PASS,
        Outcome.NOT_RUN,
        (package.artifact, state.inventory, *retention_evidence),
    )
    ledger.record_post_verification(package.operation_id, result, now)
    return result


def _verify_kms_retention(
    package: ReviewPackage,
    entry: InventoryEntry,
    evidence: tuple[EvidenceRef, ...],
    reader: EvidenceReader,
    now: datetime,
) -> None:
    from .contracts import APPROVER
    from .lifecycle_io import decode_operational_record
    from .lifecycle_models import KmsRetentionObservation

    candidates: list[KmsRetentionObservation] = []
    for reference in evidence:
        if (
            reference.kind != "kms-scheduling-observation"
            or reference.operation_id != package.operation_id
        ):
            raise ContractError("POST_VERIFY_RETENTION_EVIDENCE_KIND")
        observation = decode_operational_record(
            reader.read(reference.path, reference.sha256, reference.byte_count),
            KmsRetentionObservation,
        )
        if observation.address == entry.address:
            candidates.append(observation)
    if len(candidates) != 1:
        raise ContractError("POST_VERIFY_KMS_SCHEDULING_EVIDENCE_REQUIRED")
    record = candidates[0]
    scheduled = parse_utc_timestamp(record.scheduled_at, "original KMS schedule")
    deletion = parse_utc_timestamp(record.deletion_at, "approved KMS deletion")
    observed = parse_utc_timestamp(record.observed_at, "KMS observation")
    if (
        record.operation_id != package.operation_id
        or record.account_id != package.account_id
        or record.region != package.region
        or record.key_identity != entry.native_identity
        or record.window_days != 7
        or record.follow_up_owner != APPROVER
        or not record.scheduling_approval_id
        or not scheduled <= observed <= now < deletion
        or (now - observed).total_seconds() > 900
        or deletion != scheduled + timedelta(days=7)
        or parse_utc_timestamp(record.native_deletion_at, "native KMS deletion") != deletion
        or entry.scheduled_deletion_at != record.native_deletion_at
        or entry.cost_bearing is not False
    ):
        raise ContractError("POST_VERIFY_KMS_SCHEDULE_MISMATCH_OR_OVERDUE")


def verify_w6_004_cleanliness(residual_classes: tuple[str, ...]) -> str:
    """Classify final W6-004 residue without discovery or deletion."""

    from .destroy import validate_w6_004_final_residue

    validate_w6_004_final_residue(residual_classes)
    return "W6-004 CLEANLINESS CONTRACT SATISFIED - NATIVE DISCOVERY REQUIRED"
