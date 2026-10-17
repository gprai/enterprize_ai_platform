"""Authorization-first orchestration for bounded W9-003 model governance."""

from __future__ import annotations

from datetime import UTC, datetime
from threading import RLock
from typing import TypeVar, cast

from enterprise_ai_platform.agent.authorization import authorization_reference
from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.model_supply_chain import SupplyChainPolicy, require_registry_eligible
from enterprise_ai_platform.retrieval.models import (
    CLASSIFICATION_RANK,
    AuthContext,
    Classification,
    Role,
)
from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
)

from .contracts import ModelPackageStore, RegistryAuthorizer
from .errors import (
    RegistryAdmissionError,
    RegistryAuthorizationError,
    RegistryValidationError,
)
from .models import (
    ApprovalDecision,
    AuditExport,
    AuditRecord,
    CleanupPlan,
    KnownGoodReference,
    ModelPackageManifest,
    PackageApproval,
    PromotionApproval,
    PromotionRequest,
    PromotionResult,
    RegistryRecord,
    RollbackApproval,
    RollbackRequest,
    RollbackResult,
)
from .policy import RegistryPolicy
from .serialization import fingerprint

ResultT = TypeVar("ResultT")


class TenantRegistryAuthorizer:
    """Require active same-tenant authorization before registry-store access."""

    def authorize(
        self,
        *,
        tenant_reference_sha256: str,
        subject_reference_sha256: str,
        authorization_reference_sha256: str | None,
        classification: Classification,
        required_role: Role,
        auth_context: AuthContext,
        now: datetime,
    ) -> None:
        if not auth_context.is_active(now) or required_role not in auth_context.roles:
            raise RegistryAuthorizationError(
                f"active {required_role.value} authorization is required"
            )
        if hash_identifier(auth_context.tenant_id) != tenant_reference_sha256:
            raise RegistryAuthorizationError("tenant authorization failed")
        if hash_identifier(auth_context.subject_id) != subject_reference_sha256:
            raise RegistryAuthorizationError("subject authorization failed")
        if (
            authorization_reference_sha256 is not None
            and authorization_reference(auth_context) != authorization_reference_sha256
        ):
            raise RegistryAuthorizationError("authorization context differs")
        if CLASSIFICATION_RANK[auth_context.clearance] < CLASSIFICATION_RANK[classification]:
            raise RegistryAuthorizationError("classification clearance is insufficient")


class ModelRegistryService:
    def __init__(
        self,
        *,
        policy: RegistryPolicy,
        supply_chain_policy: SupplyChainPolicy,
        authorizer: RegistryAuthorizer,
        store: ModelPackageStore,
    ) -> None:
        self._policy = policy
        self._supply_chain_policy = supply_chain_policy
        self._authorizer = authorizer
        self._store = store
        self._active_global = 0
        self._active_by_tenant: dict[str, int] = {}
        self._registration_results: dict[str, tuple[str, RegistryRecord]] = {}
        self._promotion_results: dict[str, tuple[str, PromotionResult]] = {}
        self._rollback_results: dict[str, tuple[str, RollbackResult]] = {}
        self._lock = RLock()

    @staticmethod
    def _require_utc(now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() != UTC.utcoffset(now):
            raise RegistryValidationError("service time must use UTC")

    def _require_supply_chain(self, package: ModelPackageManifest, now: datetime) -> None:
        if (
            package.supply_chain_eligibility.policy_sha256
            != self._supply_chain_policy.identity_sha256
        ):
            raise RegistryValidationError("supply-chain policy identity differs")
        require_registry_eligible(
            package.supply_chain_eligibility,
            artifact_source_uri=package.artifact.source_uri,
            artifact_sha256=package.artifact.sha256,
            container_image_digest=package.container.image_digest,
            training_request_identity_sha256=package.training_request_identity_sha256,
            experiment_run_identity_sha256=package.experiment_run_identity_sha256,
            evaluation_report_sha256=package.model_card.evaluation_report_sha256,
            tenant_reference_sha256=package.tenant_reference_sha256,
            classification=package.classification.value,
            now=now,
        )

    def _start(self, tenant_reference_sha256: str) -> None:
        with self._lock:
            if self._active_global >= self._policy.limits.global_active_mutations:
                raise RegistryAdmissionError("global registry concurrency exceeded")
            if (
                self._active_by_tenant.get(tenant_reference_sha256, 0)
                >= self._policy.limits.per_tenant_active_mutations
            ):
                raise RegistryAdmissionError("tenant registry concurrency exceeded")
            self._active_global += 1
            self._active_by_tenant[tenant_reference_sha256] = (
                self._active_by_tenant.get(tenant_reference_sha256, 0) + 1
            )

    def _finish(self, tenant_reference_sha256: str) -> None:
        with self._lock:
            self._active_global -= 1
            self._active_by_tenant[tenant_reference_sha256] -= 1

    @staticmethod
    def _replay(
        completed: dict[str, tuple[str, ResultT]],
        idempotency_key: str,
        identity: str,
    ) -> ResultT | None:
        prior = completed.get(idempotency_key)
        if prior is None:
            return None
        prior_identity, result = prior
        if prior_identity != identity:
            raise RegistryAdmissionError("idempotency key conflicts with another input")
        return result

    def register(
        self,
        package: ModelPackageManifest,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> RegistryRecord:
        self._require_utc(now)
        self._authorizer.authorize(
            tenant_reference_sha256=package.tenant_reference_sha256,
            subject_reference_sha256=package.registrant_reference_sha256,
            authorization_reference_sha256=package.authorization_reference_sha256,
            classification=package.classification,
            required_role=Role.ADMIN,
            auth_context=auth_context,
            now=now,
        )
        if package.policy_sha256 != self._policy.identity_sha256:
            raise RegistryValidationError("package policy identity differs")
        if now >= package.deadline_at:
            raise RegistryAdmissionError("package registration deadline has expired")
        self._require_supply_chain(package, now)
        identity = fingerprint(package)
        with self._lock:
            prior = self._replay(self._registration_results, package.idempotency_key, identity)
            if prior is not None:
                return prior
        self._start(package.tenant_reference_sha256)
        try:
            result = self._store.register(package, occurred_at=now)
            with self._lock:
                self._registration_results[package.idempotency_key] = (identity, result)
            return result
        finally:
            self._finish(package.tenant_reference_sha256)

    def review(
        self,
        package_id: str,
        approval: PackageApproval,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> RegistryRecord:
        self._require_utc(now)
        self._authorizer.authorize(
            tenant_reference_sha256=approval.tenant_reference_sha256,
            subject_reference_sha256=approval.approver_reference_sha256,
            authorization_reference_sha256=approval.authorization_reference_sha256,
            classification=Classification.PUBLIC,
            required_role=Role.REVIEWER,
            auth_context=auth_context,
            now=now,
        )
        record = self._store.get(package_id)
        self._authorizer.authorize(
            tenant_reference_sha256=record.package.tenant_reference_sha256,
            subject_reference_sha256=approval.approver_reference_sha256,
            authorization_reference_sha256=approval.authorization_reference_sha256,
            classification=record.package.classification,
            required_role=Role.REVIEWER,
            auth_context=auth_context,
            now=now,
        )
        if approval.decided_at > now:
            raise RegistryAdmissionError("package approval is future-dated")
        if approval.decision is ApprovalDecision.APPROVED and now >= approval.expires_at:
            raise RegistryAdmissionError("package approval has expired")
        self._start(record.package.tenant_reference_sha256)
        try:
            return self._store.review(package_id, approval)
        finally:
            self._finish(record.package.tenant_reference_sha256)

    def promote(
        self,
        request: PromotionRequest,
        approval: PromotionApproval,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> PromotionResult:
        self._require_utc(now)
        self._authorizer.authorize(
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.executor_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=Classification.PUBLIC,
            required_role=Role.ADMIN,
            auth_context=auth_context,
            now=now,
        )
        record = self._store.get_by_identity(request.package_identity_sha256)
        self._authorizer.authorize(
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.executor_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=record.package.classification,
            required_role=Role.ADMIN,
            auth_context=auth_context,
            now=now,
        )
        if record.package.tenant_reference_sha256 != request.tenant_reference_sha256:
            raise RegistryAuthorizationError("promotion package tenant differs")
        self._require_supply_chain(record.package, now)
        if request.policy_sha256 != self._policy.identity_sha256:
            raise RegistryValidationError("promotion policy identity differs")
        if approval.decided_at > now:
            raise RegistryAdmissionError("promotion approval is future-dated")
        if now >= request.deadline_at or now >= approval.expires_at:
            raise RegistryAdmissionError("promotion request or approval has expired")
        identity = fingerprint({"approval": approval, "request": request})
        with self._lock:
            prior = self._replay(self._promotion_results, request.idempotency_key, identity)
            if prior is not None:
                return prior
        self._start(request.tenant_reference_sha256)
        try:
            result = self._store.promote(request, approval, occurred_at=now)
            with self._lock:
                self._promotion_results[request.idempotency_key] = (identity, result)
            return result
        finally:
            self._finish(request.tenant_reference_sha256)

    def cancel(
        self,
        request: PromotionRequest,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> AuditRecord:
        self._require_utc(now)
        self._authorizer.authorize(
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.executor_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=Classification.PUBLIC,
            required_role=Role.ADMIN,
            auth_context=auth_context,
            now=now,
        )
        record = self._store.get_by_identity(request.package_identity_sha256)
        self._authorizer.authorize(
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.executor_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=record.package.classification,
            required_role=Role.ADMIN,
            auth_context=auth_context,
            now=now,
        )
        return self._store.cancel(request, occurred_at=now)

    def record_known_good(
        self,
        reference: KnownGoodReference,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> AuditRecord:
        self._require_utc(now)
        self._authorizer.authorize(
            tenant_reference_sha256=reference.tenant_reference_sha256,
            subject_reference_sha256=reference.reviewer_reference_sha256,
            authorization_reference_sha256=reference.authorization_reference_sha256,
            classification=Classification.PUBLIC,
            required_role=Role.REVIEWER,
            auth_context=auth_context,
            now=now,
        )
        record = self._store.get_by_identity(reference.package_identity_sha256)
        self._authorizer.authorize(
            tenant_reference_sha256=reference.tenant_reference_sha256,
            subject_reference_sha256=reference.reviewer_reference_sha256,
            authorization_reference_sha256=reference.authorization_reference_sha256,
            classification=record.package.classification,
            required_role=Role.REVIEWER,
            auth_context=auth_context,
            now=now,
        )
        if record.package.tenant_reference_sha256 != reference.tenant_reference_sha256:
            raise RegistryAuthorizationError("known-good package tenant differs")
        if reference.marked_at > now:
            raise RegistryValidationError("known-good evidence cannot be future-dated")
        return self._store.record_known_good(reference)

    def rollback(
        self,
        request: RollbackRequest,
        approval: RollbackApproval,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> RollbackResult:
        self._require_utc(now)
        self._authorizer.authorize(
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.executor_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=Classification.PUBLIC,
            required_role=Role.ADMIN,
            auth_context=auth_context,
            now=now,
        )
        current = self._store.get_by_identity(request.expected_current_package_sha256)
        self._authorizer.authorize(
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.executor_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=current.package.classification,
            required_role=Role.ADMIN,
            auth_context=auth_context,
            now=now,
        )
        if current.package.tenant_reference_sha256 != request.tenant_reference_sha256:
            raise RegistryAuthorizationError("rollback package tenant differs")
        if request.policy_sha256 != self._policy.identity_sha256:
            raise RegistryValidationError("rollback policy identity differs")
        if approval.decided_at > now:
            raise RegistryAdmissionError("rollback approval is future-dated")
        if now >= request.deadline_at or now >= approval.expires_at:
            raise RegistryAdmissionError("rollback request or approval has expired")
        identity = fingerprint({"approval": approval, "request": request})
        with self._lock:
            prior = self._replay(self._rollback_results, request.idempotency_key, identity)
            if prior is not None:
                return prior
        self._start(request.tenant_reference_sha256)
        try:
            result = self._store.rollback(request, approval, occurred_at=now)
            with self._lock:
                self._rollback_results[request.idempotency_key] = (identity, result)
            return result
        finally:
            self._finish(request.tenant_reference_sha256)

    def disable(self) -> None:
        self._store.disable()

    def export(self, *, now: datetime) -> AuditExport:
        self._require_utc(now)
        return self._store.export(policy_sha256=self._policy.identity_sha256, exported_at=now)

    def cleanup_plan(self, *, now: datetime) -> CleanupPlan:
        self._require_utc(now)
        return self._store.cleanup_plan(policy_sha256=self._policy.identity_sha256, now=now)


def to_serving_artifact(record: RegistryRecord) -> ArtifactIdentity:
    """Project one approved package into the existing serving identity without deploying it."""

    if record.approval_state.value != "APPROVED":
        raise RegistryValidationError("only an approved package has a serving projection")
    package = record.package
    approval = cast(str, record.latest_approval_identity_sha256)
    return ArtifactIdentity(
        model_class=ModelClass.CUSTOM,
        artifact_name=package.model_card.model_name,
        artifact_version=package.model_card.model_version,
        artifact_digest=package.artifact.sha256,
        source_uri=package.artifact.source_uri,
        license=package.model_card.license,
        approval_state=ArtifactApprovalState.APPROVED,
        approval_reference=approval,
        tenant_scope=package.tenant_reference_sha256,
        classification=package.classification.value,
        processing_region=package.artifact.region,
        training_identity_reference=package.training_request_identity_sha256,
        inference_identity_reference="NOT_AUTHORIZED",
    )
