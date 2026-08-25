"""Strict provider-neutral models for documents and authorized retrieval."""

from __future__ import annotations

import hashlib
import math
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

APPROVED_EMBEDDING_MODEL_ID = "sentence-transformers/all-MiniLM-L6-v2"
APPROVED_EMBEDDING_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
APPROVED_EMBEDDING_DIMENSION = 384
APPROVED_EMBEDDING_LICENSE = "Apache-2.0"
OBSOLETE_IDENTIFIERS = frozenset(
    {"demo", "learning", "project_owner", "internal_learning"}
)


class Classification(StrEnum):
    """Ordered information-sensitivity labels."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


CLASSIFICATION_RANK = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
}


class Role(StrEnum):
    """Approved retrieval and ingestion roles."""

    READER = "reader"
    INGESTOR = "ingestor"
    REVIEWER = "reviewer"
    ADMIN = "admin"


class PiiStatus(StrEnum):
    """PII-review states carried with every document and chunk."""

    NOT_SCANNED = "NOT_SCANNED"
    CLEAR = "CLEAR"
    REDACTED = "REDACTED"
    QUARANTINED = "QUARANTINED"
    APPROVED_EXCEPTION = "APPROVED_EXCEPTION"


class IngestionStatus(StrEnum):
    """Controlled ingestion lifecycle states."""

    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    QUARANTINED = "QUARANTINED"
    INDEXED = "INDEXED"
    FAILED = "FAILED"


class VectorMetric(StrEnum):
    """Approved collection similarity metric."""

    COSINE = "cosine"


class StrictModel(BaseModel):
    """Immutable model base that rejects unknown or silently coerced fields."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


def _require_aware(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return value


def _validate_identifier(value: str) -> str:
    normalized = value.strip()
    if normalized.casefold() in OBSOLETE_IDENTIFIERS:
        raise ValueError("obsolete identifier is not permitted")
    return normalized


class ApprovedException(StrictModel):
    """Time-bounded owner approval for indexing exceptional PII."""

    owner: str = Field(min_length=1, max_length=200)
    rationale: str = Field(min_length=1, max_length=1000)
    expires_at: datetime
    document_id: str = Field(min_length=1, max_length=256)
    entity_types: frozenset[str] = Field(min_length=1, max_length=20)

    @field_validator("owner", "document_id")
    @classmethod
    def reject_obsolete_owner(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("entity_types")
    @classmethod
    def validate_entity_types(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(_validate_identifier(value) for value in values)

    @field_validator("expires_at")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        return _require_aware(value, "expires_at")

    def is_valid(self, now: datetime) -> bool:
        return self.expires_at > _require_aware(now, "now")


class DocumentMetadata(StrictModel):
    """Metadata required on documents and their derived chunks."""

    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    source_id: str = Field(min_length=1, max_length=256)
    media_type: Literal["text/plain", "text/markdown", "application/pdf"]
    document_id: str = Field(min_length=1, max_length=256)
    document_version: str = Field(min_length=1, max_length=128)
    classification: Classification
    allowed_roles: frozenset[Role] = Field(default_factory=frozenset, max_length=4)
    allowed_groups: frozenset[str] = Field(default_factory=frozenset, max_length=100)
    data_owner: str = Field(min_length=1, max_length=200)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    pii_status: PiiStatus
    ingestion_status: IngestionStatus
    approved_exception: ApprovedException | None = None

    @field_validator(
        "tenant_id",
        "source_id",
        "document_id",
        "document_version",
        "data_owner",
    )
    @classmethod
    def reject_obsolete_identifiers(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("allowed_groups")
    @classmethod
    def validate_groups(cls, groups: frozenset[str]) -> frozenset[str]:
        return frozenset(_validate_identifier(group) for group in groups)

    @model_validator(mode="after")
    def validate_exception_shape(self) -> DocumentMetadata:
        has_exception = self.approved_exception is not None
        expects_exception = self.pii_status is PiiStatus.APPROVED_EXCEPTION
        if has_exception != expects_exception:
            raise ValueError(
                "approved_exception is required only for APPROVED_EXCEPTION PII status"
            )
        if (
            self.approved_exception is not None
            and self.approved_exception.document_id != self.document_id
        ):
            raise ValueError("approved_exception must match the exact document_id")
        return self

    def is_indexable(self, now: datetime) -> bool:
        if self.ingestion_status is not IngestionStatus.INDEXED:
            return False
        if self.pii_status in {PiiStatus.CLEAR, PiiStatus.REDACTED}:
            return True
        return bool(
            self.pii_status is PiiStatus.APPROVED_EXCEPTION
            and self.approved_exception is not None
            and self.approved_exception.is_valid(now)
        )


class Document(DocumentMetadata):
    """An approved source document before vector indexing."""

    content: str = Field(min_length=1, max_length=10_000_000)


def deterministic_chunk_id(
    *,
    tenant_id: str,
    document_id: str,
    document_version: str,
    content_hash: str,
    chunk_index: int,
) -> str:
    """Return a delimiter-safe SHA-256 identity for a document chunk."""

    values = (
        _validate_identifier(tenant_id),
        _validate_identifier(document_id),
        _validate_identifier(document_version),
        content_hash,
        str(chunk_index),
    )
    canonical = b"".join(
        len(value.encode("utf-8")).to_bytes(4, "big") + value.encode("utf-8")
        for value in values
    )
    return hashlib.sha256(canonical).hexdigest()


class Chunk(DocumentMetadata):
    """An indexable document section with a normalized embedding."""

    chunk_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    chunk_index: int = Field(ge=0)
    text: str = Field(min_length=1, max_length=1_000_000)
    embedding: tuple[float, ...]

    @field_validator("embedding")
    @classmethod
    def require_approved_normalized_vector(
        cls,
        embedding: tuple[float, ...],
    ) -> tuple[float, ...]:
        if len(embedding) != APPROVED_EMBEDDING_DIMENSION:
            raise ValueError("embedding dimension must be 384")
        if not all(math.isfinite(value) for value in embedding):
            raise ValueError("embedding values must be finite")
        norm = math.sqrt(sum(value * value for value in embedding))
        if not math.isclose(norm, 1.0, rel_tol=1e-5, abs_tol=1e-5):
            raise ValueError("embedding must be normalized")
        return embedding

    @model_validator(mode="after")
    def require_deterministic_identity(self) -> Chunk:
        expected = deterministic_chunk_id(
            tenant_id=self.tenant_id,
            document_id=self.document_id,
            document_version=self.document_version,
            content_hash=self.content_hash,
            chunk_index=self.chunk_index,
        )
        if self.chunk_id != expected:
            raise ValueError("chunk_id does not match the deterministic identity")
        return self


class RetrievedChunk(Chunk):
    """A provider-neutral scored retrieval result."""

    score: float = Field(ge=-1.0, le=1.0)


class Citation(StrictModel):
    """A stable reference from an answer to one retrieved chunk."""

    document_id: str = Field(min_length=1, max_length=256)
    document_version: str = Field(min_length=1, max_length=128)
    chunk_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    label: str = Field(min_length=1, max_length=500)


class Query(StrictModel):
    """Untrusted query input; identity and tenant data are intentionally absent."""

    text: str = Field(min_length=1, max_length=10_000)
    top_k: int = Field(default=5, ge=1, le=100)
    min_score: float = Field(default=-1.0, ge=-1.0, le=1.0)


class Answer(StrictModel):
    """A cited answer or explicit abstention."""

    text: str = Field(default="", max_length=100_000)
    citations: tuple[Citation, ...] = ()
    abstained: bool = False
    abstention_reason: str | None = Field(default=None, min_length=1, max_length=1000)

    @model_validator(mode="after")
    def validate_answer_or_abstention(self) -> Answer:
        if self.abstained:
            if self.citations:
                raise ValueError("an abstention cannot contain citations")
            if self.abstention_reason is None:
                raise ValueError("an abstention requires a reason")
        elif not self.text or not self.citations:
            raise ValueError("a non-abstaining answer requires text and citations")
        elif self.abstention_reason is not None:
            raise ValueError("a non-abstaining answer cannot have an abstention reason")
        return self


class AuthContext(StrictModel):
    """Trusted authorization context supplied separately from Query."""

    subject_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    roles: frozenset[Role] = Field(min_length=1, max_length=4)
    clearance: Classification
    groups: frozenset[str] = Field(default_factory=frozenset, max_length=100)
    issuer: str | None = Field(default=None, min_length=1, max_length=500)
    audience: str | None = Field(default=None, min_length=1, max_length=500)
    expires_at: datetime | None = None
    request_id: str | None = Field(default=None, min_length=1, max_length=256)

    @field_validator("subject_id", "tenant_id")
    @classmethod
    def reject_obsolete_identifiers(cls, value: str) -> str:
        return _validate_identifier(value)

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, groups: frozenset[str]) -> frozenset[str]:
        return frozenset(_validate_identifier(group) for group in groups)

    @field_validator("expires_at")
    @classmethod
    def validate_expiry(cls, value: datetime | None) -> datetime | None:
        return None if value is None else _require_aware(value, "expires_at")

    def is_active(self, now: datetime) -> bool:
        checked_now = _require_aware(now, "now")
        return self.expires_at is None or self.expires_at > checked_now


class CollectionSpec(StrictModel):
    """Immutable EMB-001 collection identity checked before every operation."""

    name: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
    )
    embedding_model_id: str = APPROVED_EMBEDDING_MODEL_ID
    embedding_revision: str = APPROVED_EMBEDDING_REVISION
    dimension: int = APPROVED_EMBEDDING_DIMENSION
    license: str = APPROVED_EMBEDDING_LICENSE
    normalized: bool = True
    metric: VectorMetric = VectorMetric.COSINE

    @model_validator(mode="after")
    def require_emb_001(self) -> CollectionSpec:
        self.assert_approved()
        return self

    def assert_approved(self) -> None:
        expected = (
            APPROVED_EMBEDDING_MODEL_ID,
            APPROVED_EMBEDDING_REVISION,
            APPROVED_EMBEDDING_DIMENSION,
            APPROVED_EMBEDDING_LICENSE,
            True,
            VectorMetric.COSINE,
        )
        actual = (
            self.embedding_model_id,
            self.embedding_revision,
            self.dimension,
            self.license,
            self.normalized,
            self.metric,
        )
        if actual != expected:
            raise ValueError("collection specification does not match EMB-001")


def utc_now() -> datetime:
    """Return an aware current time through one testable boundary."""

    return datetime.now(UTC)
