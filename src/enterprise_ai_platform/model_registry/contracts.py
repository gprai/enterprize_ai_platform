"""Provider-neutral dependency contracts for W9-003 model governance."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role

from .models import (
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


class RegistryAuthorizer(Protocol):
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
        """Authorize one registry mutation before the store boundary."""


class ModelPackageStore(Protocol):
    def register(
        self, package: ModelPackageManifest, *, occurred_at: datetime
    ) -> RegistryRecord: ...

    def get(self, package_id: str) -> RegistryRecord: ...

    def get_by_identity(self, package_identity_sha256: str) -> RegistryRecord: ...

    def list(self) -> tuple[RegistryRecord, ...]: ...

    def review(self, package_id: str, approval: PackageApproval) -> RegistryRecord: ...

    def promote(
        self,
        request: PromotionRequest,
        approval: PromotionApproval,
        *,
        occurred_at: datetime,
    ) -> PromotionResult: ...

    def cancel(
        self,
        request: PromotionRequest,
        *,
        occurred_at: datetime,
    ) -> AuditRecord: ...

    def record_known_good(self, reference: KnownGoodReference) -> AuditRecord: ...

    def rollback(
        self,
        request: RollbackRequest,
        approval: RollbackApproval,
        *,
        occurred_at: datetime,
    ) -> RollbackResult: ...

    def current(self, stage: PromotionStage) -> str | None: ...

    def disable(self) -> None: ...

    def export(self, *, policy_sha256: str, exported_at: datetime) -> AuditExport: ...

    def cleanup_plan(self, *, policy_sha256: str, now: datetime) -> CleanupPlan: ...

    def purge(
        self,
        package_ids: tuple[str, ...],
        *,
        audit_export_identity_sha256: str,
        owner_approval_reference_sha256: str,
        actor_reference_sha256: str,
        now: datetime,
    ) -> None: ...
