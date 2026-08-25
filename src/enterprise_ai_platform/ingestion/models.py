"""Strict schemas and bounded constants for secure document ingestion."""

from __future__ import annotations

import importlib
import json
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import (
    APPROVED_EMBEDDING_DIMENSION,
    APPROVED_EMBEDDING_MODEL_ID,
    APPROVED_EMBEDDING_REVISION,
    Classification,
    PiiStatus,
    Role,
    StrictModel,
)

from .errors import IngestionConfigurationError

SCHEMA_VERSION = "1.0"
APPROVED_DATASET_NAME = "enterprise-ai-learning-corpus-v1"
MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES_PER_RUN = 100
MAX_PDF_PAGES = 50
MAX_EXTRACTED_CHARACTERS = 2_000_000
CHUNK_TARGET_TOKENS = 200
CHUNK_OVERLAP_TOKENS = 25
EMBEDDING_BATCH_SIZE = 32
MAX_APPLICATION_ATTEMPTS = 2
RETRY_BASE_SECONDS = 0.1
MAX_RETRY_JITTER_SECONDS = 0.05
DOCUMENT_DEADLINE_SECONDS = 120.0
VECTOR_OPERATION_TIMEOUT_SECONDS = 60.0
APPROVED_TOKENIZER_ID = APPROVED_EMBEDDING_MODEL_ID
APPROVED_TOKENIZER_REVISION = APPROVED_EMBEDDING_REVISION

QUARANTINE_ENTITY_TYPES = (
    "SG_NRIC_FIN",
    "PASSPORT_NUMBER",
    "BANK_ACCOUNT",
    "PAYMENT_CARD",
    "HEALTH_INFORMATION",
    "BIOMETRIC_IDENTIFIER",
    "CREDENTIAL_SECRET",
)
REDACTION_PLACEHOLDERS = (
    ("PERSON", "<PERSON>"),
    ("EMAIL_ADDRESS", "<EMAIL_ADDRESS>"),
    ("PHONE_NUMBER", "<PHONE_NUMBER>"),
    ("LOCATION", "<LOCATION>"),
    ("IP_ADDRESS", "<IP_ADDRESS>"),
)
APPROVED_STARTER_ROWS = (
    (
        "Q1",
        "Which vector database is selected for local development and which is the AWS target?",
        ("DOC-COACHING-BLUEPRINT",),
        ("Qdrant is used locally; OpenSearch vectors is the AWS target.",),
        "ANSWER_WITH_CITATION",
        ("GROUNDED", "AUTHORIZED_SOURCE"),
    ),
    (
        "Q2",
        "Can Codex automatically run `terraform apply` or `terraform destroy`?",
        ("DOC-SOT-V1.1",),
        (
            "No. Plans require review, and apply or destroy requires explicit owner approval.",
        ),
        "ANSWER_WITH_CITATION",
        ("OWNER_APPROVAL", "NO_AUTOMATIC_MUTATION"),
    ),
    (
        "Q3",
        "What should the system do when sufficient evidence is not retrieved?",
        ("DOC-SOT-V1.1",),
        ("Safely abstain instead of fabricating an answer.",),
        "ANSWER_WITH_CITATION",
        ("ABSTENTION", "NO_FABRICATION"),
    ),
    (
        "Q4",
        "What is required before a consequential agent tool can execute?",
        ("DOC-SOT-V1.1",),
        (
            "The tool must be allowlisted, arguments validated, budgets enforced, "
            "and durable human approval recorded.",
        ),
        "ANSWER_WITH_CITATION",
        ("HUMAN_APPROVAL", "TOOL_GOVERNANCE"),
    ),
    (
        "Q5",
        "What is the approved production go-live date?",
        (),
        ("No production go-live date exists in the approved documents.",),
        "SAFE_ABSTENTION",
        ("ABSTENTION", "NO_INVENTED_DATE"),
    ),
)


def _validate_relative_source_path(value: str) -> str:
    if "\\" in value:
        raise ValueError("source_path must use a relative POSIX path")
    source_path = PurePosixPath(value)
    if (
        source_path.is_absolute()
        or any(part in {"", ".", ".."} for part in source_path.parts)
        or any(":" in part for part in source_path.parts)
    ):
        raise ValueError("source_path must use a relative POSIX path")
    return value


class IngestionRecordStatus(StrEnum):
    INDEXED = "INDEXED"
    QUARANTINED = "QUARANTINED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    COMPENSATED = "COMPENSATED"
    CANCELLED = "CANCELLED"
    ROLLBACK_INDETERMINATE = "ROLLBACK_INDETERMINATE"


class StarterOutcome(StrEnum):
    ANSWER_WITH_CITATION = "ANSWER_WITH_CITATION"
    SAFE_ABSTENTION = "SAFE_ABSTENTION"


class CorpusDocument(StrictModel):
    source_path: str = Field(min_length=1, max_length=500)
    source_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9-]*$")
    classification: Classification
    allowed_roles: tuple[Role, ...] = Field(min_length=1, max_length=4)
    allowed_groups: tuple[str, ...] = Field(max_length=100)
    data_owner: str = Field(min_length=1, max_length=200)
    media_type: Literal["text/plain", "text/markdown", "application/pdf"]

    @field_validator("source_path")
    @classmethod
    def require_relative_source_path(cls, value: str) -> str:
        return _validate_relative_source_path(value)

    @model_validator(mode="after")
    def require_unique_access_values(self) -> CorpusDocument:
        if len(set(self.allowed_roles)) != len(self.allowed_roles):
            raise ValueError("allowed_roles must not contain duplicates")
        if len(set(self.allowed_groups)) != len(self.allowed_groups):
            raise ValueError("allowed_groups must not contain duplicates")
        return self


class CorpusManifest(StrictModel):
    schema_version: str = SCHEMA_VERSION
    dataset_name: str = APPROVED_DATASET_NAME
    documents: tuple[CorpusDocument, ...] = Field(min_length=1, max_length=MAX_FILES_PER_RUN)

    @model_validator(mode="after")
    def require_exact_dataset_and_unique_sources(self) -> CorpusManifest:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported corpus manifest schema")
        if self.dataset_name != APPROVED_DATASET_NAME:
            raise ValueError("unapproved dataset name")
        source_ids = [document.source_id for document in self.documents]
        source_paths = [document.source_path for document in self.documents]
        if len(set(source_ids)) != len(source_ids):
            raise ValueError("source_id values must be unique")
        if len(set(source_paths)) != len(source_paths):
            raise ValueError("source_path values must be unique")
        return self


class PiiRedaction(StrictModel):
    entity_type: str = Field(min_length=1, max_length=100)
    placeholder: str = Field(min_length=1, max_length=100)


class PiiPolicy(StrictModel):
    schema_version: str = SCHEMA_VERSION
    quarantine_entities: tuple[str, ...]
    redactions: tuple[PiiRedaction, ...]

    @model_validator(mode="after")
    def require_exact_policy(self) -> PiiPolicy:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported PII policy schema")
        if self.quarantine_entities != QUARANTINE_ENTITY_TYPES:
            raise ValueError("quarantine entity order does not match the approved policy")
        actual_redactions = tuple(
            (redaction.entity_type, redaction.placeholder)
            for redaction in self.redactions
        )
        if actual_redactions != REDACTION_PLACEHOLDERS:
            raise ValueError("redaction policy does not match the approved placeholders")
        return self

    @property
    def placeholder_by_entity(self) -> dict[str, str]:
        return {
            redaction.entity_type: redaction.placeholder
            for redaction in self.redactions
        }


class PiiFinding(StrictModel):
    entity_type: str = Field(min_length=1, max_length=100)
    start: int = Field(ge=0)
    end: int = Field(gt=0)
    confidence: float = Field(ge=0.0, le=1.0)

    @model_validator(mode="after")
    def require_nonempty_span(self) -> PiiFinding:
        if self.end <= self.start:
            raise ValueError("PII finding end must be after start")
        return self


class StarterQuestion(StrictModel):
    id: str = Field(pattern=r"^Q[1-5]$")
    question: str = Field(min_length=1, max_length=500)
    tenant_id: str = Field(pattern=r"^tenant-a$")
    roles: tuple[Role, ...] = Field(min_length=1, max_length=4)
    clearance: Classification
    expected_source_ids: tuple[str, ...] = Field(max_length=5)
    expected_facts: tuple[str, ...] = Field(min_length=1, max_length=5)
    expected_outcome: StarterOutcome
    safety_tags: tuple[str, ...] = Field(min_length=1, max_length=10)

    @model_validator(mode="after")
    def require_unique_fixture_values(self) -> StarterQuestion:
        if len(set(self.roles)) != len(self.roles):
            raise ValueError("starter roles must be unique")
        if len(set(self.expected_source_ids)) != len(self.expected_source_ids):
            raise ValueError("starter source IDs must be unique")
        if len(set(self.safety_tags)) != len(self.safety_tags):
            raise ValueError("starter safety tags must be unique")
        return self


@dataclass(frozen=True, slots=True, repr=False)
class PiiDecision:
    status: PiiStatus
    processed_text: str
    entity_types: frozenset[str]


@dataclass(frozen=True, slots=True, repr=False)
class TextChunk:
    chunk_index: int
    text: str
    token_count: int


class IngestionManifestRecord(StrictModel):
    source_path: str = Field(min_length=1, max_length=500)
    source_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=128)
    media_type: Literal["text/plain", "text/markdown", "application/pdf"]
    status: IngestionRecordStatus
    pii_status: PiiStatus | None = None
    document_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    document_version: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    content_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    chunk_count: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, min_length=1, max_length=100)

    @field_validator("source_path")
    @classmethod
    def require_relative_source_path(cls, value: str) -> str:
        return _validate_relative_source_path(value)


class IngestionManifest(StrictModel):
    schema_version: str = SCHEMA_VERSION
    dataset_name: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=128)
    model_id: str = APPROVED_EMBEDDING_MODEL_ID
    model_revision: str = APPROVED_EMBEDDING_REVISION
    embedding_dimension: int = APPROVED_EMBEDDING_DIMENSION
    normalized_embeddings: bool = True
    tokenizer_id: str = Field(min_length=1, max_length=300)
    tokenizer_revision: str = Field(min_length=1, max_length=100)
    selected_count: int = Field(ge=0, le=MAX_FILES_PER_RUN)
    indexed_count: int = Field(ge=0, le=MAX_FILES_PER_RUN)
    quarantined_count: int = Field(ge=0, le=MAX_FILES_PER_RUN)
    failed_count: int = Field(ge=0, le=MAX_FILES_PER_RUN)
    compensated_count: int = Field(ge=0, le=MAX_FILES_PER_RUN)
    duration_ms: int = Field(ge=0)
    exit_code: int
    records: tuple[IngestionManifestRecord, ...]

    @model_validator(mode="after")
    def require_consistent_counts(self) -> IngestionManifest:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("unsupported ingestion manifest schema")
        if self.exit_code not in {0, 2, 3, 4, 5, 130}:
            raise ValueError("unsupported ingestion exit code")
        if self.selected_count != len(self.records):
            raise ValueError("selected_count must equal record count")
        if self.indexed_count != sum(
            record.status is IngestionRecordStatus.INDEXED for record in self.records
        ):
            raise ValueError("indexed_count does not match records")
        if self.quarantined_count != sum(
            record.status in {
                IngestionRecordStatus.QUARANTINED,
                IngestionRecordStatus.REJECTED,
            }
            for record in self.records
        ):
            raise ValueError("quarantined_count does not match records")
        if self.compensated_count != sum(
            record.status is IngestionRecordStatus.COMPENSATED
            for record in self.records
        ):
            raise ValueError("compensated_count does not match records")
        expected_failed = sum(
            record.status
            in {
                IngestionRecordStatus.FAILED,
                IngestionRecordStatus.CANCELLED,
                IngestionRecordStatus.ROLLBACK_INDETERMINATE,
            }
            for record in self.records
        )
        if self.failed_count != expected_failed:
            raise ValueError("failed_count does not match records")
        return self


@dataclass(frozen=True, slots=True)
class IngestionOutcome:
    manifest: IngestionManifest
    exit_code: int


_yaml: Any = importlib.import_module("yaml")
_UniqueKeyLoader: Any = type(
    "_UniqueKeyLoader",
    (_yaml.SafeLoader,),
    {},
)


def _construct_unique_mapping(
    loader: Any,
    node: Any,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise IngestionConfigurationError
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    _yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise IngestionConfigurationError
        result[key] = value
    return result


def load_corpus_manifest(path: Path) -> CorpusManifest:
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
        encoded = json.dumps(data, ensure_ascii=False)
        return CorpusManifest.model_validate_json(encoded)
    except IngestionConfigurationError:
        raise
    except Exception:
        raise IngestionConfigurationError from None


def load_starter_fixture(path: Path) -> tuple[StarterQuestion, ...]:
    try:
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line]
        records = tuple(
            StarterQuestion.model_validate_json(
                json.dumps(
                    json.loads(line, object_pairs_hook=_reject_duplicate_json_keys),
                    ensure_ascii=False,
                )
            )
            for line in lines
        )
    except IngestionConfigurationError:
        raise
    except Exception:
        raise IngestionConfigurationError from None
    if [record.id for record in records] != ["Q1", "Q2", "Q3", "Q4", "Q5"]:
        raise IngestionConfigurationError
    approved_sources = {
        "DOC-SOT-V1.1",
        "DOC-COACHING-BLUEPRINT",
        "DOC-RESTRICTED-TEST",
    }
    if any(
        not set(record.expected_source_ids).issubset(approved_sources)
        for record in records
    ):
        raise IngestionConfigurationError
    if records[-1].expected_source_ids or any(
        not record.expected_source_ids for record in records[:-1]
    ):
        raise IngestionConfigurationError
    actual_rows = tuple(
        (
            record.id,
            record.question,
            record.expected_source_ids,
            record.expected_facts,
            record.expected_outcome.value,
            record.safety_tags,
        )
        for record in records
    )
    if actual_rows != APPROVED_STARTER_ROWS or any(
        record.tenant_id != "tenant-a"
        or record.roles != (Role.READER,)
        or record.clearance is not Classification.INTERNAL
        for record in records
    ):
        raise IngestionConfigurationError
    return records


def _immutable_yaml(value: object) -> object:
    if isinstance(value, list):
        return tuple(_immutable_yaml(item) for item in value)
    if isinstance(value, dict):
        return {key: _immutable_yaml(item) for key, item in value.items()}
    return value


def load_pii_policy(path: Path) -> PiiPolicy:
    try:
        raw = path.read_text(encoding="utf-8")
        loader = _UniqueKeyLoader(raw)
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
        return PiiPolicy.model_validate(_immutable_yaml(data))
    except Exception:
        raise IngestionConfigurationError from None
