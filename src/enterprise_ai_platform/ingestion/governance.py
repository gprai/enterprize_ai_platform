"""Strict W7-001 governed-ingestion contracts and canonical identities."""

from __future__ import annotations

import hashlib
import importlib
import json
import math
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import StrictModel

from .models import (
    DOCUMENT_DEADLINE_SECONDS,
    MAX_APPLICATION_ATTEMPTS,
    MAX_RETRY_JITTER_SECONDS,
    RETRY_BASE_SECONDS,
    VECTOR_OPERATION_TIMEOUT_SECONDS,
)

W7_SCHEMA_VERSION = "w7-001.data-foundation.v1"
APPROVED_REGION = "ap-southeast-1"
APPROVED_BUCKET = "enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"
SHA256_PATTERN = r"^[0-9a-f]{64}$"


class GovernanceContractError(ValueError):
    """Raised without propagating unsafe parser or provider details."""


class ZoneName(StrEnum):
    RAW = "raw"
    QUARANTINE = "quarantine"
    PROCESSED = "processed"
    EVIDENCE = "evidence"


class MalwareStatus(StrEnum):
    CLEAN = "PASS"
    DETECTED = "DETECTED"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"


class WorkflowState(StrEnum):
    RECEIVED = "RECEIVED"
    VALIDATED = "VALIDATED"
    RESERVED = "RESERVED"
    MALWARE_PASSED = "MALWARE_PASSED"
    PII_APPROVED = "PII_APPROVED"
    PROCESSED = "PROCESSED"
    EMBEDDING_ELIGIBLE = "EMBEDDING_ELIGIBLE"
    INDEXED = "INDEXED"
    QUARANTINED = "QUARANTINED"
    DEAD_LETTERED = "DEAD_LETTERED"
    CANCELLED = "CANCELLED"


class ZoneContract(StrictModel):
    prefix: str
    retention_days: int

    @model_validator(mode="after")
    def require_approved_zone(self) -> ZoneContract:
        approved = {"raw/": 7, "quarantine/": 7, "processed/": 30, "evidence/": 30}
        if approved.get(self.prefix) != self.retention_days:
            raise ValueError("unapproved zone prefix or retention")
        return self


class RetryContract(StrictModel):
    maximum_embedding_attempts: int
    base_seconds: float
    maximum_jitter_seconds: float
    document_deadline_seconds: float
    vector_operation_timeout_seconds: float

    @model_validator(mode="after")
    def require_existing_bounds(self) -> RetryContract:
        actual = (
            self.maximum_embedding_attempts,
            self.base_seconds,
            self.maximum_jitter_seconds,
            self.document_deadline_seconds,
            self.vector_operation_timeout_seconds,
        )
        expected = (
            MAX_APPLICATION_ATTEMPTS,
            RETRY_BASE_SECONDS,
            MAX_RETRY_JITTER_SECONDS,
            DOCUMENT_DEADLINE_SECONDS,
            VECTOR_OPERATION_TIMEOUT_SECONDS,
        )
        if actual != expected or any(not math.isfinite(value) for value in actual[1:]):
            raise ValueError("retry contract differs from the existing ingestion bounds")
        return self


class CapabilityContract(StrictModel):
    malware: Literal["protocol_fake_only"]
    glue_catalog: Literal["contract_only"]
    eventbridge: Literal["s3_notification_iac_only"]
    step_functions: Literal["contract_only"]
    idempotency: Literal["protocol_in_memory_fake_only"]


class DataFoundationConfig(StrictModel):
    schema_version: Literal["w7-001.data-foundation.v1"]
    feature_id: Literal["RAG-001"]
    region: Literal["ap-southeast-1"]
    synthetic_only: Literal[True]
    classifications: tuple[Literal["PUBLIC", "INTERNAL"], Literal["PUBLIC", "INTERNAL"]]
    bucket_name: Literal["enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"]
    zones: dict[ZoneName, ZoneContract]
    retry: RetryContract
    capabilities: CapabilityContract

    @model_validator(mode="after")
    def require_exact_ordered_boundary(self) -> DataFoundationConfig:
        if self.classifications != ("PUBLIC", "INTERNAL"):
            raise ValueError("classifications must be PUBLIC then INTERNAL")
        if tuple(self.zones) != tuple(ZoneName):
            raise ValueError("zones must be raw, quarantine, processed, evidence")
        expected = {
            ZoneName.RAW: ("raw/", 7),
            ZoneName.QUARANTINE: ("quarantine/", 7),
            ZoneName.PROCESSED: ("processed/", 30),
            ZoneName.EVIDENCE: ("evidence/", 30),
        }
        if any(
            (self.zones[zone].prefix, self.zones[zone].retention_days) != contract
            for zone, contract in expected.items()
        ):
            raise ValueError("zone key, prefix, and retention mapping differs")
        return self


def _utc_z(value: datetime) -> str:
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None or offset.total_seconds() != 0:
        raise GovernanceContractError("timestamps must be UTC")
    rendered = value.astimezone(UTC).isoformat(timespec="microseconds")
    return rendered.removesuffix("+00:00") + "Z"


def _canonical_value(value: object) -> object:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="python")
    if isinstance(value, datetime):
        return _utc_z(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise GovernanceContractError("canonical object keys must be strings")
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise GovernanceContractError("canonical numbers must be finite")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise GovernanceContractError("unsupported canonical value")


def canonical_json_bytes(value: object) -> bytes:
    """Return exact compact UTF-8 JSON with one trailing newline."""

    try:
        text = json.dumps(
            _canonical_value(value),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise GovernanceContractError("value is not canonicalizable") from exc
    return (text + "\n").encode("utf-8")


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_utc(value: datetime) -> datetime:
    _utc_z(value)
    return value


class SourceIdentity(StrictModel):
    schema_version: Literal["w7-001.source.v1"]
    bucket: Literal["enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"]
    key: str = Field(min_length=5, max_length=1024, pattern=r"^raw/[a-z0-9][a-z0-9-]*/.+")
    s3_version_id: str = Field(min_length=1, max_length=1024)
    etag: str = Field(min_length=1, max_length=128)
    byte_count: int = Field(gt=0, le=5 * 1024 * 1024)
    media_type: Literal["text/plain", "text/markdown", "application/pdf"]
    original_content_sha256: str = Field(pattern=SHA256_PATTERN)


class GovernanceMetadata(StrictModel):
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=128)
    classification: Literal["PUBLIC", "INTERNAL"]
    data_owner: str = Field(min_length=1, max_length=200)
    residency_region: Literal["ap-southeast-1"]
    retention_class: Literal["raw-7d", "quarantine-7d", "processed-30d", "evidence-30d"]
    retention_until: datetime
    deletion_after: datetime

    @field_validator("retention_until", "deletion_after")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def require_ordered_deletion(self) -> GovernanceMetadata:
        if self.deletion_after < self.retention_until:
            raise ValueError("deletion cannot precede retention")
        return self


class ProcessingIdentity(StrictModel):
    event_id: str = Field(min_length=1, max_length=128)
    processing_id: str = Field(min_length=1, max_length=128)
    correlation_id: str = Field(min_length=1, max_length=128)
    attempt: int = Field(ge=1, le=MAX_APPLICATION_ATTEMPTS)
    observed_at: datetime
    policy_configuration_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("observed_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)


class CatalogColumn(StrictModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=128)
    type: Literal["string", "bigint", "timestamp"]
    nullable: bool


class CatalogContract(StrictModel):
    database_name: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=128)
    table_name: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=128)
    columns: tuple[CatalogColumn, ...] = Field(min_length=1)
    partition_keys: tuple[str, ...]
    schema_version: Literal["w7-001.catalog.v1"]
    location_prefix: Literal["processed/"]

    @model_validator(mode="after")
    def require_unique_ordered_columns(self) -> CatalogContract:
        names = tuple(column.name for column in self.columns)
        if (
            len(names) != len(set(names))
            or len(self.partition_keys) != len(set(self.partition_keys))
            or any(key not in names for key in self.partition_keys)
        ):
            raise ValueError("catalog columns and partitions must be unique and ordered")
        return self


class LineageIdentity(StrictModel):
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    prior_transition_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    malware_result_identity: str = Field(pattern=SHA256_PATTERN)
    pii_decision_identity: str = Field(pattern=SHA256_PATTERN)
    processed_object_identity: str = Field(pattern=SHA256_PATTERN)
    evidence_identity: str = Field(pattern=SHA256_PATTERN)
    downstream_handoff_identity: str = Field(pattern=SHA256_PATTERN)


class AuditRecord(StrictModel):
    previous_state: WorkflowState | None
    next_state: WorkflowState
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$", max_length=80)
    correlation_id: str = Field(min_length=1, max_length=128)
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    prior_transition_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    transition_sha256: str = Field(pattern=SHA256_PATTERN)
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)


class IngestionEvent(StrictModel):
    schema_version: Literal["w7-001.event.v1"]
    detail_type: Literal["GovernedDocumentReceived"]
    source: SourceIdentity
    governance: GovernanceMetadata
    processing: ProcessingIdentity
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    pii_disposition: Literal["CLEAR", "REDACTED", "APPROVED_EXCEPTION"]
    pii_decision_identity: str = Field(pattern=SHA256_PATTERN)
    catalog: CatalogContract

    @model_validator(mode="after")
    def require_tenant_and_retention_identity(self) -> IngestionEvent:
        if not self.source.key.startswith(f"raw/{self.governance.tenant_id}/"):
            raise ValueError("source key tenant differs from governance tenant")
        days = {
            "raw-7d": 7,
            "quarantine-7d": 7,
            "processed-30d": 30,
            "evidence-30d": 30,
        }[self.governance.retention_class]
        expected_seconds = days * 24 * 60 * 60
        actual_seconds = (
            self.governance.retention_until - self.processing.observed_at
        ).total_seconds()
        if actual_seconds != expected_seconds:
            raise ValueError("retention timestamp differs from its approved class")
        if self.governance.deletion_after != self.governance.retention_until:
            raise ValueError("deletion timestamp must equal the approved retention boundary")
        return self


class EmbeddingEligibility(StrictModel):
    schema_version: Literal["w7-001.embedding-eligibility.v1"]
    event_id: str
    processing_id: str
    correlation_id: str
    tenant_id: str
    classification: Literal["PUBLIC", "INTERNAL"]
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    malware_result_identity: str = Field(pattern=SHA256_PATTERN)
    pii_decision_identity: str = Field(pattern=SHA256_PATTERN)
    issued_at: datetime

    @field_validator("issued_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        return _require_utc(value)


_yaml: Any = importlib.import_module("yaml")


_UniqueKeyLoader: Any = type("_UniqueKeyLoader", (_yaml.SafeLoader,), {})


def _construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[object, object]:
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


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GovernanceContractError("duplicate event key")
        result[key] = value
    return result


def load_ingestion_event_json(raw: bytes | str) -> IngestionEvent:
    """Parse a strict EventBridge-compatible envelope without accepting duplicate keys."""

    try:
        text = raw.decode("utf-8", errors="strict") if isinstance(raw, bytes) else raw
        data = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
        return IngestionEvent.model_validate(data, strict=False)
    except GovernanceContractError:
        raise
    except Exception as exc:
        raise GovernanceContractError("invalid W7-001 ingestion event") from exc


def load_data_foundation_config(path: Path) -> DataFoundationConfig:
    try:
        loader = _UniqueKeyLoader(path.read_text(encoding="utf-8"))
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
        return DataFoundationConfig.model_validate(data, strict=False)
    except GovernanceContractError:
        raise
    except Exception as exc:
        raise GovernanceContractError("invalid W7-001 data-foundation configuration") from exc
