"""Strict immutable W9-002 experiment-lineage identities and records."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import Classification

from .serialization import fingerprint

SHA256_PATTERN = r"^[0-9a-f]{64}$"
COMMIT_PATTERN = r"^[0-9a-f]{40}$"
SAFE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
SAFE_KEY_PATTERN = r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"
SAFE_VALUE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+,-]{0,255}$"


class LineageModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class RunStatus(StrEnum):
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    INVALIDATED = "INVALIDATED"
    CANCELLED = "CANCELLED"


class MetricUnit(StrEnum):
    RATIO = "ratio"
    BOOLEAN = "boolean"
    MILLISECONDS = "milliseconds"
    TOKENS = "tokens"
    USD = "usd"
    COUNT = "count"


class DatasetIdentity(LineageModel):
    dataset_version: str = Field(pattern=SAFE_NAME_PATTERN)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    case_inventory_sha256: str = Field(pattern=SHA256_PATTERN)
    case_count: int = Field(gt=0, le=10_000)
    synthetic: Literal[True] = True
    production_data: Literal[False] = False
    classification: Classification

    @model_validator(mode="after")
    def require_local_classification(self) -> DatasetIdentity:
        if self.classification not in {Classification.PUBLIC, Classification.INTERNAL}:
            raise ValueError("local lineage accepts only PUBLIC or INTERNAL data")
        return self


class CodeIdentity(LineageModel):
    git_commit: str = Field(pattern=COMMIT_PATTERN)
    source_composition_sha256: str = Field(pattern=SHA256_PATTERN)


class PromptIdentity(LineageModel):
    prompt_version: str = Field(pattern=SAFE_NAME_PATTERN)
    prompt_template_sha256: str = Field(pattern=SHA256_PATTERN)


class ModelIdentity(LineageModel):
    provider: str = Field(pattern=SAFE_NAME_PATTERN)
    model_id: str = Field(pattern=SAFE_NAME_PATTERN)
    revision: str = Field(pattern=SAFE_NAME_PATTERN)
    artifact_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    license: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,79}$")
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("revision")
    @classmethod
    def reject_mutable_revision_names(cls, value: str) -> str:
        if value.casefold() in {"latest", "main", "master"}:
            raise ValueError("model revision must be immutable")
        return value


class EmbeddingIdentity(LineageModel):
    model_id: str = Field(pattern=SAFE_NAME_PATTERN)
    revision: str = Field(pattern=SAFE_NAME_PATTERN)
    dimension: Literal[384] = 384
    normalized: Literal[True] = True
    metric: Literal["cosine"] = "cosine"
    artifact_sha256: str = Field(pattern=SHA256_PATTERN)


class RetrievalIdentity(LineageModel):
    store_kind: Literal["fake", "qdrant", "opensearch"]
    collection_name: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{0,127}$")
    collection_spec_sha256: str = Field(pattern=SHA256_PATTERN)
    collection_revision: str = Field(pattern=SAFE_NAME_PATTERN)
    retrieval_policy_sha256: str = Field(pattern=SHA256_PATTERN)


class EvaluationIdentity(LineageModel):
    report_schema: Literal["w3-002.report.v1"] = "w3-002.report.v1"
    evaluator_version: Literal["w3-002.v1"] = "w3-002.v1"
    metric_version: Literal["w3-002.metrics.v1"] = "w3-002.metrics.v1"
    dataset_checksum_sha256: str = Field(pattern=SHA256_PATTERN)
    configuration_checksum_sha256: str = Field(pattern=SHA256_PATTERN)
    deterministic_payload_sha256: str = Field(pattern=SHA256_PATTERN)
    gate_status: Literal["PASS", "FAIL", "INDETERMINATE"]
    baseline_comparison_status: Literal[
        "PASS", "FAIL", "NO_APPROVED_BASELINE", "INCOMPATIBLE_BASELINE"
    ]


class ExperimentParameter(LineageModel):
    key: str = Field(pattern=SAFE_KEY_PATTERN)
    value: str = Field(pattern=SAFE_VALUE_PATTERN)
    redacted: Literal[True] = True


class ExperimentMetric(LineageModel):
    name: str = Field(pattern=SAFE_KEY_PATTERN)
    value: Decimal
    unit: MetricUnit
    derivation: str = Field(pattern=SAFE_NAME_PATTERN)

    @field_validator("value")
    @classmethod
    def require_finite_value(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("metric values must be finite")
        return value

    @model_validator(mode="after")
    def require_unit_bounds(self) -> ExperimentMetric:
        if self.unit in {MetricUnit.RATIO, MetricUnit.BOOLEAN} and not (
            Decimal("0") <= self.value <= Decimal("1")
        ):
            raise ValueError("ratio and boolean metrics must be between zero and one")
        if (
            self.unit
            in {
                MetricUnit.MILLISECONDS,
                MetricUnit.TOKENS,
                MetricUnit.USD,
                MetricUnit.COUNT,
            }
            and self.value < 0
        ):
            raise ValueError("count, duration, token, and cost metrics cannot be negative")
        return self


class ArtifactReference(LineageModel):
    kind: str = Field(pattern=SAFE_KEY_PATTERN)
    path: str = Field(min_length=1, max_length=512)
    sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Literal["PUBLIC", "INTERNAL"]
    redacted: Literal[True] = True

    @field_validator("path")
    @classmethod
    def require_safe_relative_path(cls, value: str) -> str:
        parsed = PurePosixPath(value)
        if parsed.is_absolute() or ".." in parsed.parts or "\\" in value or value.startswith("~"):
            raise ValueError("artifact paths must be safe relative POSIX paths")
        return value


class ExperimentInput(LineageModel):
    schema_version: Literal["w9-002.experiment-input.v1"] = "w9-002.experiment-input.v1"
    dataset: DatasetIdentity
    code: CodeIdentity
    prompt: PromptIdentity
    model: ModelIdentity
    embedding: EmbeddingIdentity
    retrieval: RetrievalIdentity
    evaluation: EvaluationIdentity
    parameters: tuple[ExperimentParameter, ...] = Field(max_length=128)
    metrics: tuple[ExperimentMetric, ...] = Field(max_length=32)
    artifacts: tuple[ArtifactReference, ...] = Field(max_length=16)

    @model_validator(mode="after")
    def require_ordered_unique_values(self) -> ExperimentInput:
        for values, attribute in (
            (self.parameters, "key"),
            (self.metrics, "name"),
            (self.artifacts, "path"),
        ):
            keys = tuple(getattr(item, attribute) for item in values)
            if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
                raise ValueError(f"{attribute} values must be sorted and unique")
        if self.dataset.manifest_sha256 != self.evaluation.dataset_checksum_sha256:
            raise ValueError("dataset and evaluation identities differ")
        return self


class RunEnvelope(LineageModel):
    schema_version: Literal["w9-002.run-envelope.v1"] = "w9-002.run-envelope.v1"
    run_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    correlation_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    subject_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Classification
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_at: datetime
    deadline_at: datetime

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("run timestamps must use UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_bounded_deadline(self) -> RunEnvelope:
        if self.classification not in {Classification.PUBLIC, Classification.INTERNAL}:
            raise ValueError("local lineage accepts only PUBLIC or INTERNAL data")
        if self.deadline_at <= self.requested_at:
            raise ValueError("run deadline must follow request time")
        if (self.deadline_at - self.requested_at).total_seconds() > 900:
            raise ValueError("run deadline exceeds nine hundred seconds")
        return self


class ExperimentRun(LineageModel):
    schema_version: Literal["w9-002.run-record.v1"] = "w9-002.run-record.v1"
    envelope: RunEnvelope
    input_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    experiment_input: ExperimentInput
    status: RunStatus
    safe_reason_code: str | None = Field(default=None, pattern=r"^[A-Z][A-Z0-9_]{0,79}$")
    deployment_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"
    promotion_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"
    completed_at: datetime | None = None

    @field_validator("completed_at")
    @classmethod
    def require_optional_utc(cls, value: datetime | None) -> datetime | None:
        if value is not None and (
            value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value)
        ):
            raise ValueError("completion timestamp must use UTC")
        return value

    @model_validator(mode="after")
    def require_terminal_shape(self) -> ExperimentRun:
        if self.input_identity_sha256 != fingerprint(self.experiment_input):
            raise ValueError("run input identity differs from its canonical input")
        if self.status is RunStatus.RUNNING:
            if self.safe_reason_code is not None or self.completed_at is not None:
                raise ValueError("running records cannot be terminal")
        elif self.completed_at is None:
            raise ValueError("terminal records require completion time")
        if self.status is RunStatus.COMPLETED and self.safe_reason_code is not None:
            raise ValueError("completed records cannot contain a failure reason")
        if (
            self.status in {RunStatus.INVALIDATED, RunStatus.CANCELLED}
            and not self.safe_reason_code
        ):
            raise ValueError("non-success terminal records require a safe reason")
        return self


class MetricDelta(LineageModel):
    name: str = Field(pattern=SAFE_KEY_PATTERN)
    unit: MetricUnit
    baseline: Decimal
    candidate: Decimal
    delta: Decimal

    @model_validator(mode="after")
    def require_exact_delta(self) -> MetricDelta:
        if self.delta != self.candidate - self.baseline:
            raise ValueError("metric delta is inconsistent")
        return self


class ExperimentComparison(LineageModel):
    schema_version: Literal["w9-002.comparison.v1"] = "w9-002.comparison.v1"
    baseline_run_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    candidate_run_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    compatible_context_sha256: str = Field(pattern=SHA256_PATTERN)
    metric_deltas: tuple[MetricDelta, ...] = Field(max_length=32)
    deployment_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"
    promotion_approval: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"

    @model_validator(mode="after")
    def require_distinct_runs(self) -> ExperimentComparison:
        if self.baseline_run_id == self.candidate_run_id:
            raise ValueError("comparison requires two distinct runs")
        names = tuple(metric.name for metric in self.metric_deltas)
        if names != tuple(sorted(names)) or len(names) != len(set(names)):
            raise ValueError("comparison metric deltas must be sorted and unique")
        return self


class RedactedLineageExport(LineageModel):
    schema_version: Literal["w9-002.lineage-export.v1"] = "w9-002.lineage-export.v1"
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    exported_at: datetime
    records: tuple[ExperimentRun, ...] = Field(max_length=100)

    @field_validator("exported_at")
    @classmethod
    def require_export_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("export timestamp must use UTC")
        return value

    @field_validator("records")
    @classmethod
    def require_sorted_unique_records(
        cls, values: tuple[ExperimentRun, ...]
    ) -> tuple[ExperimentRun, ...]:
        run_ids = tuple(record.envelope.run_id for record in values)
        if run_ids != tuple(sorted(run_ids)) or len(run_ids) != len(set(run_ids)):
            raise ValueError("exported runs must be sorted and unique")
        if any(record.status is RunStatus.RUNNING for record in values):
            raise ValueError("redacted export cannot contain an active run")
        return values

    @model_validator(mode="after")
    def require_policy_bound_records(self) -> RedactedLineageExport:
        if any(record.envelope.policy_sha256 != self.policy_sha256 for record in self.records):
            raise ValueError("exported run policy identity differs")
        return self


class CleanupPlan(LineageModel):
    schema_version: Literal["w9-002.cleanup-plan.v1"] = "w9-002.cleanup-plan.v1"
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    exact_run_ids: tuple[str, ...] = Field(max_length=100)
    retain_redacted_export: Literal[True] = True
    retention_days: Literal[180] = 180
    delete_shared_resources: Literal[False] = False
    owner_approval_required: Literal[True] = True
    status: Literal["NOT_RUN"] = "NOT_RUN"

    @field_validator("exact_run_ids")
    @classmethod
    def require_sorted_unique_run_ids(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if values != tuple(sorted(values)) or len(values) != len(set(values)):
            raise ValueError("cleanup run IDs must be sorted and unique")
        if any(
            len(value) != 36 or any(character not in "0123456789abcdef-" for character in value)
            for value in values
        ):
            raise ValueError("cleanup run IDs must use canonical lowercase UUID text")
        return values
