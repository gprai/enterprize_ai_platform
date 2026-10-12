"""Fail-closed W7-003 privacy classification and exact lifecycle contracts."""

from __future__ import annotations

import hashlib
import importlib
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    CollectionSpec,
    Role,
    StrictModel,
)
from enterprise_ai_platform.retrieval.vector_store import VectorStore

from .governance import GovernanceContractError, canonical_sha256
from .models import PiiFinding, PiiPolicy
from .pii import PiiAnalyzer, apply_pii_policy

SCHEMA_VERSION = "w7-003.privacy-lifecycle.v1"
APPROVED_REGION = "ap-southeast-1"
APPROVAL_VALIDITY_SECONDS = 15 * 60
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class EvidenceState(StrEnum):
    PASSED = "PASS"
    FAIL = "FAIL"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


class PrivacyDisposition(StrEnum):
    CLEAR = "CLEAR"
    REDACTED = "REDACTED"
    QUARANTINED = "QUARANTINED"
    APPROVED_EXCEPTION = "APPROVED_EXCEPTION"


class LifecycleOperation(StrEnum):
    DELETE = "DELETE"
    QUARANTINE_CLEANUP = "QUARANTINE_CLEANUP"
    REINDEX = "REINDEX"


class RetainedResourceKind(StrEnum):
    SHARED_BUCKET = "SHARED_BUCKET"
    SHARED_INDEX = "SHARED_INDEX"
    SHARED_KMS_KEY = "SHARED_KMS_KEY"
    SERVICE_LINKED_ROLE = "SERVICE_LINKED_ROLE"


class PrivacyLifecycleError(RuntimeError):
    """Safe W7-003 failure without source content or provider details."""


class RetentionConfig(StrictModel):
    raw: Literal[7]
    quarantine: Literal[7]
    processed: Literal[30]
    evidence: Literal[30]


class PrivacyConfig(StrictModel):
    presidio: Literal["injected_adapter_only"]
    macie: Literal["protocol_fake_only"]
    evidence_content: Literal["redacted_metadata_only"]


class LifecycleConfig(StrictModel):
    approval_validity_seconds: Literal[900]
    concurrency: Literal[1]
    discovery_maximum_attempts: Literal[2]
    destructive_retry: Literal["disabled"]
    durable_approval_store: Literal["protocol_in_memory_fake_only"]
    live_cloud_execution: Literal["separate_owner_approval_required"]
    shared_resource_deletion: Literal["prohibited"]


class PrivacyLifecycleConfig(StrictModel):
    schema_version: Literal["w7-003.privacy-lifecycle.v1"]
    feature_id: Literal["RAG-001"]
    region: Literal["ap-southeast-1"]
    synthetic_only: Literal[True]
    classifications: tuple[Literal["PUBLIC", "INTERNAL"], Literal["PUBLIC", "INTERNAL"]]
    retention_days: RetentionConfig
    privacy: PrivacyConfig
    lifecycle: LifecycleConfig

    @model_validator(mode="after")
    def require_exact_order(self) -> PrivacyLifecycleConfig:
        if self.classifications != ("PUBLIC", "INTERNAL"):
            raise ValueError("classifications must be PUBLIC then INTERNAL")
        return self

    @property
    def identity(self) -> str:
        return canonical_sha256(self)


class MacieDiscovery(StrictModel):
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    state: EvidenceState
    classification: Literal["PUBLIC", "INTERNAL"] | None = None
    finding_types: tuple[str, ...] = ()
    result_identity_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_complete_pass(self) -> MacieDiscovery:
        if self.state is EvidenceState.PASSED and self.classification is None:
            raise ValueError("Macie-compatible PASS requires classification")
        if self.state is not EvidenceState.PASSED and self.classification is not None:
            raise ValueError("non-PASS discovery cannot grant classification")
        return self


class PrivacyAssessment(StrictModel):
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    disposition: PrivacyDisposition
    classification: Literal["PUBLIC", "INTERNAL"]
    entity_types: tuple[str, ...]
    redacted_text: str | None = Field(default=None, max_length=10_000_000)
    macie_result_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    assessment_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$", max_length=80)


class PrivacyReleaseApproval(StrictModel):
    approval_id: str = Field(min_length=1, max_length=256)
    owner: str = Field(min_length=1, max_length=200)
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    entity_types: frozenset[str] = Field(min_length=1, max_length=20)
    issued_at: datetime
    expires_at: datetime

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("release approval timestamps must be UTC")
        return value

    @model_validator(mode="after")
    def require_bounded_release(self) -> PrivacyReleaseApproval:
        if self.expires_at <= self.issued_at:
            raise ValueError("release approval expiry must follow issue time")
        if (self.expires_at - self.issued_at).total_seconds() > APPROVAL_VALIDITY_SECONDS:
            raise ValueError("release approval validity exceeds 15 minutes")
        return self


class SourceObjectVersion(StrictModel):
    bucket: str = Field(min_length=3, max_length=255)
    key: str = Field(min_length=1, max_length=1024)
    version_id: str = Field(min_length=1, max_length=1024)
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=128)
    document_id: str = Field(min_length=1, max_length=256)
    document_version: str = Field(min_length=1, max_length=128)
    content_sha256: str = Field(pattern=SHA256_PATTERN)

    @property
    def identity(self) -> str:
        return canonical_sha256(self)


class EvidenceArchiveReceipt(StrictModel):
    evidence_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    encryption_key_arn: str = Field(min_length=20, max_length=2048)
    contains_source_content: Literal[False]
    archived_at: datetime

    @field_validator("archived_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("archived_at must be UTC")
        return value


class RetainedResource(StrictModel):
    kind: RetainedResourceKind
    resource_identity: str = Field(min_length=1, max_length=2048)
    retained_reason: str = Field(min_length=1, max_length=500)


class DestructiveApproval(StrictModel):
    approval_id: str = Field(min_length=1, max_length=256)
    operation: LifecycleOperation
    owner: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=128)
    plan_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    target_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    issued_at: datetime
    expires_at: datetime
    one_time_use: Literal[True]

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("approval timestamps must be UTC")
        return value

    @model_validator(mode="after")
    def require_bounded_validity(self) -> DestructiveApproval:
        if self.expires_at <= self.issued_at:
            raise ValueError("approval expiry must follow issue time")
        if (self.expires_at - self.issued_at).total_seconds() > APPROVAL_VALIDITY_SECONDS:
            raise ValueError("approval validity exceeds 15 minutes")
        return self


class LifecyclePlan(StrictModel):
    schema_version: Literal["w7-003.lifecycle-plan.v1"]
    operation: LifecycleOperation
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=128)
    source: SourceObjectVersion
    index_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    evidence_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    collection: CollectionSpec
    retained_resources: tuple[RetainedResource, ...] = Field(min_length=1)
    created_at: datetime
    destruction_eligible_at: datetime

    @field_validator("created_at", "destruction_eligible_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("created_at must be UTC")
        return value

    @model_validator(mode="after")
    def require_exact_scope(self) -> LifecyclePlan:
        if self.source.tenant_id != self.tenant_id:
            raise ValueError("source tenant differs from lifecycle plan")
        kinds = {item.kind for item in self.retained_resources}
        if RetainedResourceKind.SHARED_KMS_KEY not in kinds:
            raise ValueError("shared KMS key must be retained explicitly")
        if len(kinds) != len(self.retained_resources):
            raise ValueError("retained-resource kinds must be unique")
        return self

    @property
    def identity(self) -> str:
        return canonical_sha256(self)


class LifecycleReceipt(StrictModel):
    plan_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    approval_id: str
    state: EvidenceState
    index_count_before: int = Field(ge=0)
    index_count_after: int | None = Field(default=None, ge=0)
    source_absent: bool | None = None
    evidence_identity_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$", max_length=80)
    completed_at: datetime


@runtime_checkable
class MacieBoundary(Protocol):
    async def discover(self, source: SourceObjectVersion) -> MacieDiscovery: ...


@runtime_checkable
class EvidenceArchive(Protocol):
    async def archive_redacted_metadata(self, plan: LifecyclePlan) -> EvidenceArchiveReceipt: ...


@runtime_checkable
class VersionedObjectStore(Protocol):
    async def delete_exact_version(self, source: SourceObjectVersion) -> None: ...

    async def exact_version_exists(self, source: SourceObjectVersion) -> bool: ...


@runtime_checkable
class KmsBoundary(Protocol):
    async def is_usable(self, key_arn: str) -> bool: ...


@runtime_checkable
class ApprovalUseStore(Protocol):
    def consume(self, approval: DestructiveApproval, *, now: datetime) -> bool: ...


def assess_privacy(
    *,
    text: str,
    source_identity_sha256: str,
    classification: Literal["PUBLIC", "INTERNAL"],
    presidio_findings: Sequence[PiiFinding],
    macie: MacieDiscovery,
    redacted_text: str | None = None,
    release_approval: PrivacyReleaseApproval | None = None,
    now: datetime | None = None,
) -> PrivacyAssessment:
    """Combine provider-neutral findings without allowing permissive fallback."""

    del text
    if macie.source_identity_sha256 != source_identity_sha256:
        reason = "DISCOVERY_IDENTITY_MISMATCH"
        disposition = PrivacyDisposition.QUARANTINED
    elif macie.state is not EvidenceState.PASSED:
        reason = "DISCOVERY_NOT_PASS"
        disposition = PrivacyDisposition.QUARANTINED
    elif macie.classification != classification:
        reason = "CLASSIFICATION_MISMATCH"
        disposition = PrivacyDisposition.QUARANTINED
    elif release_approval is not None and presidio_findings:
        evaluated_at = now or release_approval.issued_at
        exact_entities = frozenset(item.entity_type for item in presidio_findings)
        if (
            release_approval.source_identity_sha256 != source_identity_sha256
            or release_approval.entity_types != exact_entities
            or evaluated_at < release_approval.issued_at
            or evaluated_at >= release_approval.expires_at
        ):
            reason = "RELEASE_APPROVAL_INVALID"
            disposition = PrivacyDisposition.QUARANTINED
        else:
            reason = "OWNER_EXCEPTION_APPROVED"
            disposition = PrivacyDisposition.APPROVED_EXCEPTION
    elif presidio_findings and redacted_text is None:
        reason = "PII_REDACTION_REQUIRED"
        disposition = PrivacyDisposition.QUARANTINED
    elif presidio_findings:
        reason = "PII_REDACTED"
        disposition = PrivacyDisposition.REDACTED
    else:
        reason = "PRIVACY_CLEAR"
        disposition = PrivacyDisposition.CLEAR
    entity_types = tuple(sorted({item.entity_type for item in presidio_findings}))
    payload = {
        "source_identity_sha256": source_identity_sha256,
        "disposition": disposition.value,
        "classification": classification,
        "entity_types": entity_types,
        "macie_result_identity_sha256": macie.result_identity_sha256,
        "safe_reason_code": reason,
    }
    return PrivacyAssessment(
        source_identity_sha256=source_identity_sha256,
        disposition=disposition,
        classification=classification,
        entity_types=entity_types,
        redacted_text=redacted_text if disposition is PrivacyDisposition.REDACTED else None,
        macie_result_identity_sha256=macie.result_identity_sha256,
        assessment_identity_sha256=canonical_sha256(payload),
        safe_reason_code=reason,
    )


class PrivacyCoordinator:
    def __init__(
        self,
        *,
        analyzer: PiiAnalyzer,
        macie: MacieBoundary,
        pii_policy: PiiPolicy,
    ) -> None:
        self._analyzer = analyzer
        self._macie = macie
        self._pii_policy = pii_policy

    async def assess(
        self,
        *,
        text: str,
        source: SourceObjectVersion,
        classification: Literal["PUBLIC", "INTERNAL"],
        release_approval: PrivacyReleaseApproval | None = None,
        now: datetime | None = None,
    ) -> PrivacyAssessment:
        try:
            findings = await self._analyzer.analyze(text)
            discovery = await self._macie.discover(source)
            policy_decision = apply_pii_policy(text, findings, self._pii_policy)
            redacted_text = (
                policy_decision.processed_text
                if policy_decision.status.value == PrivacyDisposition.REDACTED.value
                else None
            )
        except Exception:
            findings = ()
            redacted_text = None
            failure_payload = {
                "source_identity_sha256": source.identity,
                "state": EvidenceState.INDETERMINATE.value,
                "safe_reason_code": "PRIVACY_CLASSIFICATION_FAILED",
            }
            discovery = MacieDiscovery(
                source_identity_sha256=source.identity,
                state=EvidenceState.INDETERMINATE,
                result_identity_sha256=canonical_sha256(failure_payload),
            )
        return assess_privacy(
            text=text,
            source_identity_sha256=source.identity,
            classification=classification,
            presidio_findings=findings,
            macie=discovery,
            redacted_text=redacted_text,
            release_approval=release_approval,
            now=now,
        )


class LifecycleCoordinator:
    """Execute one approved destructive plan with a witnessed order of operations."""

    def __init__(
        self,
        *,
        vector_store: VectorStore,
        object_store: VersionedObjectStore,
        evidence_archive: EvidenceArchive,
        kms: KmsBoundary,
        approval_store: ApprovalUseStore,
    ) -> None:
        self._vectors = vector_store
        self._objects = object_store
        self._archive = evidence_archive
        self._kms = kms
        self._approvals = approval_store

    async def delete(
        self,
        plan: LifecyclePlan,
        approval: DestructiveApproval,
        auth_context: AuthContext,
        *,
        now: datetime,
    ) -> LifecycleReceipt:
        if plan.operation not in {LifecycleOperation.DELETE, LifecycleOperation.QUARANTINE_CLEANUP}:
            raise PrivacyLifecycleError("UNAPPROVED_OPERATION")
        if Role.ADMIN not in auth_context.roles or auth_context.tenant_id != plan.tenant_id:
            raise PrivacyLifecycleError("DELETION_NOT_AUTHORIZED")
        if (
            approval.operation is not plan.operation
            or approval.tenant_id != plan.tenant_id
            or approval.plan_identity_sha256 != plan.identity
            or approval.target_identity_sha256 != plan.source.identity
            or now < approval.issued_at
            or now >= approval.expires_at
            or not self._approvals.consume(approval, now=now)
        ):
            raise PrivacyLifecycleError("DESTRUCTIVE_APPROVAL_INVALID")
        if now < plan.destruction_eligible_at:
            raise PrivacyLifecycleError("RETENTION_NOT_EXPIRED")

        count_before = await self._vectors.count_by_document_version(
            plan.collection,
            plan.source.document_id,
            plan.source.document_version,
            auth_context,
        )
        receipt = await self._archive.archive_redacted_metadata(plan)
        if (
            receipt.source_identity_sha256 != plan.source.identity
            or receipt.payload_sha256 != plan.evidence_payload_sha256
            or receipt.contains_source_content
            or not await self._kms.is_usable(receipt.encryption_key_arn)
        ):
            raise PrivacyLifecycleError("EVIDENCE_ARCHIVE_NOT_VERIFIED")

        try:
            await self._vectors.delete_by_document_version(
                plan.collection,
                plan.source.document_id,
                plan.source.document_version,
                auth_context,
            )
            count_after = await self._vectors.count_by_document_version(
                plan.collection,
                plan.source.document_id,
                plan.source.document_version,
                auth_context,
            )
        except Exception:
            return LifecycleReceipt(
                plan_identity_sha256=plan.identity,
                approval_id=approval.approval_id,
                state=EvidenceState.INDETERMINATE,
                index_count_before=count_before,
                evidence_identity_sha256=receipt.evidence_identity_sha256,
                safe_reason_code="INDEX_DELETION_INDETERMINATE",
                completed_at=now,
            )
        if count_after != 0:
            return LifecycleReceipt(
                plan_identity_sha256=plan.identity,
                approval_id=approval.approval_id,
                state=EvidenceState.INDETERMINATE,
                index_count_before=count_before,
                index_count_after=count_after,
                evidence_identity_sha256=receipt.evidence_identity_sha256,
                safe_reason_code="INDEX_ABSENCE_NOT_PROVEN",
                completed_at=now,
            )

        source_absent: bool | None
        try:
            await self._objects.delete_exact_version(plan.source)
            source_absent = not await self._objects.exact_version_exists(plan.source)
        except Exception:
            source_absent = None
        if not source_absent:
            return LifecycleReceipt(
                plan_identity_sha256=plan.identity,
                approval_id=approval.approval_id,
                state=EvidenceState.INDETERMINATE,
                index_count_before=count_before,
                index_count_after=count_after,
                source_absent=source_absent,
                evidence_identity_sha256=receipt.evidence_identity_sha256,
                safe_reason_code="SOURCE_ABSENCE_NOT_PROVEN",
                completed_at=now,
            )
        return LifecycleReceipt(
            plan_identity_sha256=plan.identity,
            approval_id=approval.approval_id,
            state=EvidenceState.PASSED,
            index_count_before=count_before,
            index_count_after=count_after,
            source_absent=True,
            evidence_identity_sha256=receipt.evidence_identity_sha256,
            safe_reason_code="EXACT_VERSION_DELETION_VERIFIED",
            completed_at=now,
        )


class ReindexRequest(StrictModel):
    schema_version: Literal["w7-003.reindex.v1"]
    source: SourceObjectVersion
    prior_manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    privacy_assessment_sha256: str = Field(pattern=SHA256_PATTERN)
    quality_report_sha256: str = Field(pattern=SHA256_PATTERN)
    new_manifest_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def require_new_manifest(self) -> ReindexRequest:
        if self.new_manifest_sha256 == self.prior_manifest_sha256:
            raise ValueError("re-index requires a new manifest identity")
        return self


_yaml: Any = importlib.import_module("yaml")
_UniqueKeyLoader: Any = type("_UniqueKeyLoader", (_yaml.SafeLoader,), {})


def _construct_unique_mapping(
    loader: Any,
    node: Any,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise GovernanceContractError("duplicate configuration key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    _yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_privacy_lifecycle_config(path: Path) -> PrivacyLifecycleConfig:
    try:
        loader = _UniqueKeyLoader(path.read_text(encoding="utf-8"))
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
        return PrivacyLifecycleConfig.model_validate(data, strict=False)
    except GovernanceContractError:
        raise
    except Exception as exc:
        raise GovernanceContractError("invalid W7-003 privacy-lifecycle configuration") from exc


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def utc_now() -> datetime:
    return datetime.now(UTC)
