"""Strict identities and schemas for deterministic W7-002 processing."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml  # type: ignore[import-untyped]
from pydantic import Field, model_validator

from enterprise_ai_platform.ingestion.governance import (
    EmbeddingEligibility,
    canonical_sha256,
)
from enterprise_ai_platform.retrieval.models import StrictModel

SHA256_PATTERN = r"^[0-9a-f]{64}$"
APPROVED_REQUIRED_FIELDS = (
    "document_id",
    "tenant_id",
    "classification",
    "source_identity_sha256",
    "content_sha256",
    "normalized_content_sha256",
)


class ProcessingContractError(ValueError):
    """Raised when a processing contract cannot be loaded safely."""


class ProcessingState(StrEnum):
    RECEIVED = "RECEIVED"
    EXTRACTED = "EXTRACTED"
    VALIDATED = "VALIDATED"
    CURATED = "CURATED"
    QUARANTINED = "QUARANTINED"
    DEAD_LETTERED = "DEAD_LETTERED"
    CANCELLED = "CANCELLED"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"


class QualityStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - quality outcome, not a credential
    WARNING = "WARNING"
    FAIL = "FAIL"
    INSUFFICIENT_SAMPLE = "INSUFFICIENT_SAMPLE"


class MetricName(StrEnum):
    EXTRACTION_FAILURE = "w7_processing_extraction_failure_total"
    PII_DETECTION_FAILURE = "w7_processing_pii_detection_failure_total"
    EMBEDDING_FAILURE = "w7_processing_embedding_failure_total"
    INDEXING_FAILURE = "w7_processing_indexing_failure_total"
    SCHEMA_DRIFT = "w7_processing_schema_drift_total"
    VOLUME_DRIFT = "w7_processing_volume_drift_total"
    DUPLICATE = "w7_processing_duplicate_total"


class QualityThresholds(StrictModel):
    required_fields: tuple[str, ...]
    minimum_drift_sample: Literal[20]
    volume_minimum_ratio: float
    volume_maximum_ratio: float
    duplicate_pass_maximum_ratio: float
    duplicate_warning_maximum_ratio: float

    @model_validator(mode="after")
    def require_approved_fields(self) -> QualityThresholds:
        if self.required_fields != APPROVED_REQUIRED_FIELDS:
            raise ValueError("required fields differ from the approved ordered contract")
        actual = (
            self.volume_minimum_ratio,
            self.volume_maximum_ratio,
            self.duplicate_pass_maximum_ratio,
            self.duplicate_warning_maximum_ratio,
        )
        if actual != (0.5, 2.0, 0.05, 0.1):
            raise ValueError("quality thresholds differ from the owner-approved values")
        return self


class ProcessingBounds(StrictModel):
    maximum_attempts: Literal[2]
    document_deadline_seconds: float
    concurrency: Literal[1]

    @model_validator(mode="after")
    def require_approved_deadline(self) -> ProcessingBounds:
        if self.document_deadline_seconds != 120.0:
            raise ValueError("document deadline differs from the inherited approved bound")
        return self


class ReplayBounds(StrictModel):
    maximum_documents: Literal[100]
    maximum_document_bytes: Literal[5_242_880]
    maximum_total_bytes: Literal[104_857_600]
    maximum_duration_seconds: Literal[900]
    maximum_source_age_hours: Literal[24]
    single_tenant: Literal[True]
    immutable_version_required: Literal[True]


class CapabilityContract(StrictModel):
    quality_engine: Literal["provider_neutral_compatible"]
    checkpoint_store: Literal["protocol_in_memory_fake_only"]
    glue_spark: Literal["compatible_interface_only"]
    network_access: Literal["disabled"]
    destructive_reprocessing: Literal["separate_owner_approval_required"]


class ProcessingConfig(StrictModel):
    schema_version: Literal["w7-002.processing-config.v1"]
    feature_id: Literal["RAG-001"]
    region: Literal["ap-southeast-1"]
    classifications: tuple[Literal["PUBLIC", "INTERNAL"], ...]
    quality: QualityThresholds
    processing: ProcessingBounds
    replay: ReplayBounds
    capabilities: CapabilityContract

    @model_validator(mode="after")
    def require_approved_classifications(self) -> ProcessingConfig:
        if self.classifications != ("PUBLIC", "INTERNAL"):
            raise ValueError("classifications differ from the approved ordered contract")
        return self

    @property
    def identity(self) -> str:
        return canonical_sha256(self)


class ReplaySourceIdentity(StrictModel):
    schema_version: Literal["w7-002.replay-source.v1"]
    bucket: Literal["enterprise-ai-platform-526338061652-ap-southeast-1-sandbox"]
    key: str = Field(min_length=5, max_length=1024, pattern=r"^raw/[a-z0-9][a-z0-9-]*/.+")
    version_id: str = Field(min_length=1, max_length=1024)
    etag: str = Field(min_length=1, max_length=128)
    byte_count: int = Field(gt=0, le=5_242_880)
    media_type: Literal["text/plain", "text/markdown", "application/pdf"]
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    upstream_source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    selected_at: datetime

    @model_validator(mode="after")
    def require_utc_selection(self) -> ReplaySourceIdentity:
        if self.selected_at.tzinfo is None or self.selected_at.utcoffset() is None:
            raise ValueError("selected_at must include a UTC offset")
        if self.selected_at.astimezone(UTC) != self.selected_at:
            raise ValueError("selected_at must be UTC")
        return self

    @property
    def identity(self) -> str:
        return canonical_sha256(self)


class PartitionMetadata(StrictModel):
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=128)
    classification: Literal["PUBLIC", "INTERNAL"]
    processing_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")


class DocumentRequest(StrictModel):
    schema_version: Literal["w7-002.processing-request.v1"]
    document_id: str = Field(min_length=1, max_length=128)
    eligibility: EmbeddingEligibility
    source: ReplaySourceIdentity
    partition: PartitionMetadata
    observed_fields: tuple[str, ...] = APPROVED_REQUIRED_FIELDS

    @model_validator(mode="after")
    def bind_handoff_and_source(self) -> DocumentRequest:
        if self.partition.tenant_id != self.eligibility.tenant_id:
            raise ValueError("partition tenant differs from eligibility tenant")
        if self.partition.classification != self.eligibility.classification:
            raise ValueError("partition classification differs from eligibility classification")
        if not self.source.key.startswith(f"raw/{self.eligibility.tenant_id}/"):
            raise ValueError("source tenant differs from eligibility tenant")
        if self.source.content_sha256 != self.eligibility.content_sha256:
            raise ValueError("replay source content differs from the approved handoff")
        if self.source.upstream_source_identity_sha256 != self.eligibility.source_identity_sha256:
            raise ValueError("replay source identity differs from the approved handoff")
        if self.observed_fields != APPROVED_REQUIRED_FIELDS:
            raise ValueError("schema drift detected")
        return self


class ProcessingBatchRequest(StrictModel):
    schema_version: Literal["w7-002.batch.v1"]
    batch_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$", max_length=128)
    expected_document_count: int = Field(ge=1, le=100)
    documents: tuple[DocumentRequest, ...] = Field(min_length=1, max_length=100)
    requested_at: datetime
    dry_run: bool
    destructive_reprocessing_approved: Literal[False] = False
    policy_configuration_sha256: str = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def enforce_replay_scope(self) -> ProcessingBatchRequest:
        if self.requested_at.tzinfo is None or self.requested_at.utcoffset() is None:
            raise ValueError("requested_at must include a UTC offset")
        if self.requested_at.astimezone(UTC) != self.requested_at:
            raise ValueError("requested_at must be UTC")
        if any(document.eligibility.tenant_id != self.tenant_id for document in self.documents):
            raise ValueError("replay cannot expand beyond one tenant")
        document_ids = tuple(document.document_id for document in self.documents)
        if len(document_ids) != len(set(document_ids)):
            raise ValueError("document identities must be unique within a batch")
        if sum(document.source.byte_count for document in self.documents) > 104_857_600:
            raise ValueError("replay exceeds the approved total byte bound")
        if any(
            document.eligibility.issued_at > self.requested_at
            or (self.requested_at - document.eligibility.issued_at).total_seconds() > 86_400
            or document.source.selected_at > self.requested_at
            or (self.requested_at - document.source.selected_at).total_seconds() > 86_400
            for document in self.documents
        ):
            raise ValueError("replay handoff or immutable source selection is stale or future")
        return self


class PreparedDocument(StrictModel):
    document_id: str
    eligibility: EmbeddingEligibility
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    normalized_text: str = Field(min_length=1, repr=False)
    normalized_content_sha256: str = Field(pattern=SHA256_PATTERN)
    partition: PartitionMetadata


class QualityObservation(StrictModel):
    check_name: str = Field(pattern=r"^[a-z][a-z0-9_]*$", max_length=80)
    status: QualityStatus
    observed: str = Field(min_length=1, max_length=80)
    threshold: str = Field(min_length=1, max_length=80)
    safe_reason_code: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]*$")


class MetricCount(StrictModel):
    name: MetricName
    count: int = Field(ge=0)
    total: int = Field(ge=1)
    rate: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def require_exact_rate(self) -> MetricCount:
        if self.count > self.total or self.rate != self.count / self.total:
            raise ValueError("metric rate differs from its exact count and population")
        return self


class DocumentDecision(StrictModel):
    document_id: str
    state: ProcessingState
    state_history: tuple[ProcessingState, ...] = Field(min_length=2)
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]*$", max_length=80)
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    normalized_content_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    checkpoint_sequence: int = Field(ge=1)


class QualityReport(StrictModel):
    schema_version: Literal["w7-002.quality-report.v1"]
    batch_id: str
    tenant_id: str
    policy_configuration_sha256: str = Field(pattern=SHA256_PATTERN)
    threshold_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    status: QualityStatus
    input_count: int = Field(ge=1, le=100)
    unique_count: int = Field(ge=0, le=100)
    duplicate_count: int = Field(ge=0, le=100)
    quarantined_count: int = Field(ge=0, le=100)
    observations: tuple[QualityObservation, ...]
    metrics: tuple[MetricCount, ...]
    generated_at: datetime

    @property
    def identity(self) -> str:
        return canonical_sha256(self)


class BatchResult(StrictModel):
    schema_version: Literal["w7-002.batch-result.v1"]
    batch_id: str
    decisions: tuple[DocumentDecision, ...]
    quality_report: QualityReport
    dry_run: bool


class ProcessingCheckpoint(StrictModel):
    schema_version: Literal["w7-002.checkpoint.v1"]
    batch_id: str
    document_id: str
    sequence: int = Field(ge=1)
    terminal_state: ProcessingState
    source_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    normalized_content_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    quality_report_sha256: str = Field(pattern=SHA256_PATTERN)


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(loader: Any, node: Any, deep: bool = False) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "mapping", node.start_mark, "duplicate key", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_processing_config(path: Path) -> ProcessingConfig:
    """Load strict UTF-8 YAML while rejecting aliases and duplicate keys."""

    try:
        raw = path.read_bytes()
        if len(raw) > 65_536 or raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise ProcessingContractError("processing config is not bounded UTF-8")
        text = raw.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise ProcessingContractError("YAML aliases are not permitted")
        loader = _UniqueKeyLoader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
        return ProcessingConfig.model_validate(value, strict=False)
    except ProcessingContractError:
        raise
    except Exception as exc:
        raise ProcessingContractError("processing config is invalid") from exc
