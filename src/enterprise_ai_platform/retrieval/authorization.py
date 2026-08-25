"""Deterministic authorization applied before and after vector retrieval."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime

from .errors import VectorStoreAuthorizationError, VectorStoreValidationError
from .models import (
    CLASSIFICATION_RANK,
    AuthContext,
    Chunk,
    Classification,
    DocumentMetadata,
    PiiStatus,
    Role,
    utc_now,
)


@dataclass(frozen=True, slots=True)
class RetrievalPolicy:
    """Provider-neutral pre-query policy compiled by each adapter."""

    tenant_id: str
    classifications: tuple[Classification, ...]
    roles: tuple[Role, ...]
    groups: tuple[str, ...]
    allowed_pii_statuses: tuple[PiiStatus, ...]
    evaluated_at: datetime


def require_active_context(auth_context: AuthContext, now: datetime | None = None) -> datetime:
    evaluated_at = utc_now() if now is None else now
    if not auth_context.is_active(evaluated_at):
        raise VectorStoreAuthorizationError
    return evaluated_at


def build_retrieval_policy(
    auth_context: AuthContext,
    now: datetime | None = None,
) -> RetrievalPolicy:
    """Build exact tenant, clearance and ACL inputs before a provider query."""

    evaluated_at = require_active_context(auth_context, now)
    classifications = tuple(
        classification
        for classification in Classification
        if CLASSIFICATION_RANK[classification]
        <= CLASSIFICATION_RANK[auth_context.clearance]
    )
    return RetrievalPolicy(
        tenant_id=auth_context.tenant_id,
        classifications=classifications,
        roles=tuple(sorted(auth_context.roles, key=lambda role: role.value)),
        groups=tuple(sorted(auth_context.groups)),
        allowed_pii_statuses=(
            PiiStatus.CLEAR,
            PiiStatus.REDACTED,
            PiiStatus.APPROVED_EXCEPTION,
        ),
        evaluated_at=evaluated_at,
    )


def is_retrieval_authorized(
    metadata: DocumentMetadata,
    auth_context: AuthContext,
    now: datetime | None = None,
) -> bool:
    """Revalidate a returned result without granting admin bypasses."""

    try:
        evaluated_at = require_active_context(auth_context, now)
    except VectorStoreAuthorizationError:
        return False
    if metadata.tenant_id != auth_context.tenant_id:
        return False
    if CLASSIFICATION_RANK[metadata.classification] > CLASSIFICATION_RANK[auth_context.clearance]:
        return False
    if not metadata.is_indexable(evaluated_at):
        return False
    role_match = bool(metadata.allowed_roles.intersection(auth_context.roles))
    group_match = bool(metadata.allowed_groups.intersection(auth_context.groups))
    return role_match or group_match


def require_upsert_authorized(
    chunks: Iterable[Chunk],
    auth_context: AuthContext,
    now: datetime | None = None,
) -> tuple[Chunk, ...]:
    """Allow ingestion-owned, same-tenant, indexable vector upserts only."""

    evaluated_at = require_active_context(auth_context, now)
    materialized = tuple(chunks)
    if not materialized:
        raise VectorStoreValidationError
    if Role.INGESTOR not in auth_context.roles:
        raise VectorStoreAuthorizationError
    for chunk in materialized:
        if chunk.tenant_id != auth_context.tenant_id:
            raise VectorStoreAuthorizationError
        if not chunk.is_indexable(evaluated_at):
            raise VectorStoreValidationError
        if chunk.pii_status is PiiStatus.APPROVED_EXCEPTION:
            require_ingestion_authorized(
                chunk,
                auth_context,
                detected_entity_types=(
                    ()
                    if chunk.approved_exception is None
                    else chunk.approved_exception.entity_types
                ),
                now=evaluated_at,
            )
    return materialized


def require_ingestion_authorized(
    metadata: DocumentMetadata,
    auth_context: AuthContext,
    *,
    detected_entity_types: Iterable[str] = (),
    now: datetime | None = None,
) -> datetime:
    """Authorize one exact tenant/document/PII boundary before provider calls."""

    evaluated_at = require_active_context(auth_context, now)
    if metadata.tenant_id != auth_context.tenant_id:
        raise VectorStoreAuthorizationError
    if Role.INGESTOR not in auth_context.roles:
        raise VectorStoreAuthorizationError
    if metadata.pii_status is not PiiStatus.APPROVED_EXCEPTION:
        if metadata.pii_status not in {PiiStatus.CLEAR, PiiStatus.REDACTED}:
            raise VectorStoreValidationError
        return evaluated_at

    exception = metadata.approved_exception
    if (
        exception is None
        or Role.ADMIN not in auth_context.roles
        or exception.owner != metadata.data_owner
        or exception.document_id != metadata.document_id
        or exception.entity_types != frozenset(detected_entity_types)
        or not exception.is_valid(evaluated_at)
    ):
        raise VectorStoreAuthorizationError
    return evaluated_at


def require_delete_authorized(auth_context: AuthContext, now: datetime | None = None) -> None:
    """Allow only tenant-bound ingestors or admins to delete document vectors."""

    require_active_context(auth_context, now)
    if not auth_context.roles.intersection({Role.INGESTOR, Role.ADMIN}):
        raise VectorStoreAuthorizationError
