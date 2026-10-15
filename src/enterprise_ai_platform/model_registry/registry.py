"""Bounded process-local model registry with atomic immutable transitions."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from threading import RLock

from .errors import RegistryAdmissionError, RegistryStateError, RegistryValidationError
from .models import (
    ApprovalDecision,
    ApprovalState,
    AuditAction,
    AuditEvent,
    AuditExport,
    AuditRecord,
    CleanupPlan,
    KnownGoodReference,
    ModelPackageManifest,
    PackageApproval,
    PromotionApproval,
    PromotionRequest,
    PromotionResult,
    PromotionStage,
    RegistryRecord,
    RollbackApproval,
    RollbackRequest,
    RollbackResult,
)
from .serialization import fingerprint


def _require_utc(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise RegistryValidationError("registry timestamps must use UTC")


class InMemoryModelRegistry:
    """Provide registry semantics without files, environment access, SDKs, or network."""

    def __init__(self, *, maximum_packages: int = 100, maximum_audit_events: int = 1000) -> None:
        if maximum_packages != 100 or maximum_audit_events != 1000:
            raise RegistryValidationError("registry limits differ from the approved policy")
        self._maximum_packages = maximum_packages
        self._maximum_audit_events = maximum_audit_events
        self._records: dict[str, RegistryRecord] = {}
        self._identities: dict[str, str] = {}
        self._stages: dict[PromotionStage, str] = {}
        self._generations: dict[PromotionStage, int] = {}
        self._known_good: dict[PromotionStage, KnownGoodReference] = {}
        self._cancelled_requests: set[str] = set()
        self._applied_requests: set[str] = set()
        self._promotion_results: dict[str, PromotionResult] = {}
        self._audit: list[AuditRecord] = []
        self._disabled = False
        self._latest_export_identity: str | None = None
        self._lock = RLock()

    @property
    def disabled(self) -> bool:
        with self._lock:
            return self._disabled

    def _ensure_enabled(self) -> None:
        if self._disabled:
            raise RegistryStateError("model registry is disabled")

    def _prepare_audit(
        self,
        *,
        action: AuditAction,
        tenant_reference_sha256: str,
        actor_reference_sha256: str,
        package_identity_sha256: str,
        request_identity_sha256: str,
        detail: object,
        occurred_at: datetime,
    ) -> AuditRecord:
        if len(self._audit) >= self._maximum_audit_events:
            raise RegistryAdmissionError("audit-event limit exceeded")
        event = AuditEvent(
            sequence=len(self._audit) + 1,
            previous_event_sha256=(
                None if not self._audit else self._audit[-1].event_identity_sha256
            ),
            action=action,
            tenant_reference_sha256=tenant_reference_sha256,
            actor_reference_sha256=actor_reference_sha256,
            package_identity_sha256=package_identity_sha256,
            request_identity_sha256=request_identity_sha256,
            detail_identity_sha256=fingerprint(detail),
            occurred_at=occurred_at,
        )
        return AuditRecord(event=event, event_identity_sha256=fingerprint(event))

    def register(self, package: ModelPackageManifest, *, occurred_at: datetime) -> RegistryRecord:
        _require_utc(occurred_at)
        identity = fingerprint(package)
        record = RegistryRecord(package=package, package_identity_sha256=identity)
        with self._lock:
            self._ensure_enabled()
            if package.package_id in self._records or identity in self._identities:
                raise RegistryAdmissionError("package identity already exists")
            if len(self._records) >= self._maximum_packages:
                raise RegistryAdmissionError("retained-package limit exceeded")
            audit = self._prepare_audit(
                action=AuditAction.REGISTERED,
                tenant_reference_sha256=package.tenant_reference_sha256,
                actor_reference_sha256=package.registrant_reference_sha256,
                package_identity_sha256=identity,
                request_identity_sha256=identity,
                detail=record,
                occurred_at=occurred_at,
            )
            self._records[package.package_id] = record
            self._identities[identity] = package.package_id
            self._audit.append(audit)
            return record

    def get(self, package_id: str) -> RegistryRecord:
        with self._lock:
            try:
                return self._records[package_id]
            except KeyError:
                raise RegistryStateError("package does not exist") from None

    def get_by_identity(self, package_identity_sha256: str) -> RegistryRecord:
        with self._lock:
            try:
                return self.get(self._identities[package_identity_sha256])
            except KeyError:
                raise RegistryStateError("package identity does not exist") from None

    def list(self) -> tuple[RegistryRecord, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))

    def review(self, package_id: str, approval: PackageApproval) -> RegistryRecord:
        with self._lock:
            self._ensure_enabled()
            current = self.get(package_id)
            if current.approval_state is not ApprovalState.PENDING_REVIEW:
                raise RegistryStateError("package has already been reviewed")
            if approval.package_identity_sha256 != current.package_identity_sha256:
                raise RegistryValidationError("approval package identity differs")
            if approval.tenant_reference_sha256 != current.package.tenant_reference_sha256:
                raise RegistryValidationError("approval tenant identity differs")
            if approval.policy_sha256 != current.package.policy_sha256:
                raise RegistryValidationError("approval policy identity differs")
            if approval.requester_reference_sha256 != current.package.registrant_reference_sha256:
                raise RegistryValidationError("approval requester identity differs")
            next_state = (
                ApprovalState.APPROVED
                if approval.decision is ApprovalDecision.APPROVED
                else ApprovalState.REJECTED
            )
            approval_identity = fingerprint(approval)
            updated = current.model_copy(
                update={
                    "approval_state": next_state,
                    "latest_approval_identity_sha256": approval_identity,
                }
            )
            updated = RegistryRecord.model_validate(updated.model_dump(mode="python"), strict=True)
            audit = self._prepare_audit(
                action=AuditAction.REVIEWED,
                tenant_reference_sha256=current.package.tenant_reference_sha256,
                actor_reference_sha256=approval.approver_reference_sha256,
                package_identity_sha256=current.package_identity_sha256,
                request_identity_sha256=approval_identity,
                detail=approval,
                occurred_at=approval.decided_at,
            )
            self._records[package_id] = updated
            self._audit.append(audit)
            return updated

    def _retire_if_unreferenced(
        self,
        records: dict[str, RegistryRecord],
        stages: dict[PromotionStage, str],
        package_identity_sha256: str | None,
        *,
        occurred_at: datetime,
    ) -> None:
        if package_identity_sha256 is None or package_identity_sha256 in stages.values():
            return
        package_id = self._identities[package_identity_sha256]
        current = records[package_id]
        retired = current.model_copy(
            update={"approval_state": ApprovalState.SUPERSEDED, "retired_at": occurred_at}
        )
        records[package_id] = RegistryRecord.model_validate(
            retired.model_dump(mode="python"), strict=True
        )

    def promote(
        self,
        request: PromotionRequest,
        approval: PromotionApproval,
        *,
        occurred_at: datetime,
    ) -> PromotionResult:
        _require_utc(occurred_at)
        request_identity = fingerprint(request)
        approval_identity = fingerprint(approval)
        with self._lock:
            self._ensure_enabled()
            if request.request_id in self._cancelled_requests:
                raise RegistryStateError("cancelled promotion cannot be applied")
            if request.request_id in self._applied_requests:
                raise RegistryStateError("promotion request has already been applied")
            record = self.get_by_identity(request.package_identity_sha256)
            if record.approval_state is not ApprovalState.APPROVED:
                raise RegistryStateError("only an approved package can be promoted")
            if record.latest_approval_identity_sha256 != request.package_approval_identity_sha256:
                raise RegistryValidationError("reviewed package approval identity differs")
            if request.policy_sha256 != record.package.policy_sha256:
                raise RegistryValidationError("promotion policy identity differs")
            if approval.promotion_request_identity_sha256 != request_identity:
                raise RegistryValidationError("promotion approval request identity differs")
            if approval.package_identity_sha256 != request.package_identity_sha256:
                raise RegistryValidationError("promotion approval package identity differs")
            if approval.target_stage is not request.target_stage:
                raise RegistryValidationError("promotion approval target stage differs")
            if approval.requester_reference_sha256 != request.executor_reference_sha256:
                raise RegistryValidationError("promotion approval requester identity differs")
            if request.source_stage is PromotionStage.STAGING and (
                self._stages.get(PromotionStage.STAGING) != request.package_identity_sha256
            ):
                raise RegistryStateError("production promotion requires the exact staged package")
            current_target = self._stages.get(request.target_stage)
            if current_target != request.expected_target_package_sha256:
                raise RegistryStateError("target stage changed after review")
            next_generation = self._generations.get(request.target_stage, 0) + 1
            detail = {
                "approval_identity_sha256": approval_identity,
                "request": request,
            }
            audit = self._prepare_audit(
                action=AuditAction.PROMOTED,
                tenant_reference_sha256=request.tenant_reference_sha256,
                actor_reference_sha256=request.executor_reference_sha256,
                package_identity_sha256=request.package_identity_sha256,
                request_identity_sha256=request_identity,
                detail=detail,
                occurred_at=occurred_at,
            )
            result = PromotionResult(
                request_identity_sha256=request_identity,
                package_identity_sha256=request.package_identity_sha256,
                target_stage=request.target_stage,
                prior_target_package_sha256=current_target,
                generation=next_generation,
                audit_event_sha256=audit.event_identity_sha256,
            )
            next_stages = dict(self._stages)
            next_stages[request.target_stage] = request.package_identity_sha256
            next_records = dict(self._records)
            self._retire_if_unreferenced(
                next_records,
                next_stages,
                current_target,
                occurred_at=occurred_at,
            )
            self._records = next_records
            self._stages = next_stages
            self._generations[request.target_stage] = next_generation
            self._applied_requests.add(request.request_id)
            self._promotion_results[audit.event_identity_sha256] = result
            self._audit.append(audit)
            return result

    def cancel(
        self,
        request: PromotionRequest,
        *,
        occurred_at: datetime,
    ) -> AuditRecord:
        _require_utc(occurred_at)
        request_identity = fingerprint(request)
        with self._lock:
            self._ensure_enabled()
            if request.request_id in self._applied_requests:
                raise RegistryStateError("applied promotion cannot be cancelled; use rollback")
            if request.request_id in self._cancelled_requests:
                raise RegistryStateError("promotion request is already cancelled")
            self.get_by_identity(request.package_identity_sha256)
            audit = self._prepare_audit(
                action=AuditAction.PROMOTION_CANCELLED,
                tenant_reference_sha256=request.tenant_reference_sha256,
                actor_reference_sha256=request.executor_reference_sha256,
                package_identity_sha256=request.package_identity_sha256,
                request_identity_sha256=request_identity,
                detail=request,
                occurred_at=occurred_at,
            )
            self._cancelled_requests.add(request.request_id)
            self._audit.append(audit)
            return audit

    def record_known_good(self, reference: KnownGoodReference) -> AuditRecord:
        with self._lock:
            self._ensure_enabled()
            if self._stages.get(reference.stage) != reference.package_identity_sha256:
                raise RegistryStateError("known-good package is not current in its stage")
            try:
                promotion = self._promotion_results[reference.promotion_event_sha256]
            except KeyError:
                raise RegistryValidationError("known-good promotion event does not exist") from None
            if (
                promotion.package_identity_sha256 != reference.package_identity_sha256
                or promotion.target_stage is not reference.stage
            ):
                raise RegistryValidationError("known-good promotion evidence differs")
            audit = self._prepare_audit(
                action=AuditAction.KNOWN_GOOD_RECORDED,
                tenant_reference_sha256=reference.tenant_reference_sha256,
                actor_reference_sha256=reference.reviewer_reference_sha256,
                package_identity_sha256=reference.package_identity_sha256,
                request_identity_sha256=fingerprint(reference),
                detail=reference,
                occurred_at=reference.marked_at,
            )
            self._known_good[reference.stage] = reference
            self._audit.append(audit)
            return audit

    def rollback(
        self,
        request: RollbackRequest,
        approval: RollbackApproval,
        *,
        occurred_at: datetime,
    ) -> RollbackResult:
        _require_utc(occurred_at)
        request_identity = fingerprint(request)
        with self._lock:
            self._ensure_enabled()
            if request.request_id in self._applied_requests:
                raise RegistryStateError("rollback request has already been applied")
            current = self._stages.get(request.stage)
            if current != request.expected_current_package_sha256:
                raise RegistryStateError("rollback current package identity differs")
            try:
                known_good = self._known_good[request.stage]
            except KeyError:
                raise RegistryStateError("no known-good package exists for this stage") from None
            if fingerprint(known_good) != request.known_good_reference_sha256:
                raise RegistryValidationError("known-good reference identity differs")
            if known_good.package_identity_sha256 != request.known_good_package_sha256:
                raise RegistryValidationError("known-good package identity differs")
            if request.policy_sha256 != self.get_by_identity(current).package.policy_sha256:
                raise RegistryValidationError("rollback policy identity differs")
            if approval.rollback_request_identity_sha256 != request_identity:
                raise RegistryValidationError("rollback approval request identity differs")
            if (
                approval.current_package_sha256 != current
                or approval.known_good_package_sha256 != request.known_good_package_sha256
            ):
                raise RegistryValidationError("rollback approval package identities differ")
            if approval.requester_reference_sha256 != request.executor_reference_sha256:
                raise RegistryValidationError("rollback approval requester identity differs")
            next_generation = self._generations.get(request.stage, 0) + 1
            audit = self._prepare_audit(
                action=AuditAction.ROLLED_BACK,
                tenant_reference_sha256=request.tenant_reference_sha256,
                actor_reference_sha256=request.executor_reference_sha256,
                package_identity_sha256=request.known_good_package_sha256,
                request_identity_sha256=request_identity,
                detail={"approval": approval, "request": request},
                occurred_at=occurred_at,
            )
            result = RollbackResult(
                request_identity_sha256=request_identity,
                failed_package_sha256=current,
                restored_package_sha256=request.known_good_package_sha256,
                stage=request.stage,
                generation=next_generation,
                audit_event_sha256=audit.event_identity_sha256,
            )
            next_stages = dict(self._stages)
            next_stages[request.stage] = request.known_good_package_sha256
            next_records = dict(self._records)
            restored_id = self._identities[request.known_good_package_sha256]
            restored = next_records[restored_id].model_copy(
                update={"approval_state": ApprovalState.APPROVED, "retired_at": None}
            )
            next_records[restored_id] = RegistryRecord.model_validate(
                restored.model_dump(mode="python"), strict=True
            )
            self._retire_if_unreferenced(
                next_records,
                next_stages,
                current,
                occurred_at=occurred_at,
            )
            self._records = next_records
            self._stages = next_stages
            self._generations[request.stage] = next_generation
            self._applied_requests.add(request.request_id)
            self._audit.append(audit)
            return result

    def current(self, stage: PromotionStage) -> str | None:
        with self._lock:
            return self._stages.get(stage)

    def disable(self) -> None:
        with self._lock:
            self._disabled = True

    def export(self, *, policy_sha256: str, exported_at: datetime) -> AuditExport:
        _require_utc(exported_at)
        with self._lock:
            if not self._disabled:
                raise RegistryStateError("registry must be disabled before audit export")
            exported = AuditExport(
                policy_sha256=policy_sha256,
                exported_at=exported_at,
                records=tuple(self._audit),
            )
            self._latest_export_identity = fingerprint(exported)
            return exported

    def cleanup_plan(self, *, policy_sha256: str, now: datetime) -> CleanupPlan:
        _require_utc(now)
        with self._lock:
            protected = set(self._stages.values()) | {
                reference.package_identity_sha256 for reference in self._known_good.values()
            }
            threshold = now - timedelta(days=180)
            eligible = tuple(
                sorted(
                    record.package.package_id
                    for record in self._records.values()
                    if record.approval_state is ApprovalState.SUPERSEDED
                    and record.retired_at is not None
                    and record.retired_at <= threshold
                    and record.package_identity_sha256 not in protected
                )
            )
            return CleanupPlan(
                policy_sha256=policy_sha256,
                exact_package_ids=eligible,
                audit_export_identity_sha256=self._latest_export_identity,
            )

    def purge(
        self,
        package_ids: tuple[str, ...],
        *,
        audit_export_identity_sha256: str,
        owner_approval_reference_sha256: str,
        actor_reference_sha256: str,
        now: datetime,
    ) -> None:
        _require_utc(now)
        with self._lock:
            if not self._disabled:
                raise RegistryStateError("registry must be disabled before deletion")
            if self._latest_export_identity != audit_export_identity_sha256:
                raise RegistryStateError("deletion is not bound to the latest audit export")
            if any(
                re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in (owner_approval_reference_sha256, actor_reference_sha256)
            ):
                raise RegistryValidationError("deletion requires hashed owner approval and actor")
            if package_ids != tuple(sorted(set(package_ids))):
                raise RegistryValidationError("deletion package IDs must be sorted and unique")
            plan = self.cleanup_plan(policy_sha256="0" * 64, now=now)
            if package_ids != plan.exact_package_ids:
                raise RegistryStateError("deletion must name the exact eligible inventory")
            prepared: list[tuple[str, str, AuditRecord]] = []
            previous = self._audit[-1].event_identity_sha256 if self._audit else None
            for offset, package_id in enumerate(package_ids, start=1):
                record = self.get(package_id)
                event = AuditEvent(
                    sequence=len(self._audit) + offset,
                    previous_event_sha256=previous,
                    action=AuditAction.DELETED,
                    tenant_reference_sha256=record.package.tenant_reference_sha256,
                    actor_reference_sha256=actor_reference_sha256,
                    package_identity_sha256=record.package_identity_sha256,
                    request_identity_sha256=fingerprint(
                        {
                            "audit_export_identity_sha256": audit_export_identity_sha256,
                            "package_id": package_id,
                        }
                    ),
                    detail_identity_sha256=fingerprint(
                        {
                            "owner_approval_reference_sha256": owner_approval_reference_sha256,
                            "record": record,
                        }
                    ),
                    occurred_at=now,
                )
                audit = AuditRecord(event=event, event_identity_sha256=fingerprint(event))
                prepared.append((package_id, record.package_identity_sha256, audit))
                previous = audit.event_identity_sha256
            if len(self._audit) + len(prepared) > self._maximum_audit_events:
                raise RegistryAdmissionError("audit-event limit exceeded")
            for package_id, identity, audit in prepared:
                del self._records[package_id]
                del self._identities[identity]
                self._audit.append(audit)
