"""Strict immutable identities and outcomes for governed W9-001 training."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from enterprise_ai_platform.retrieval.models import Classification

SHA256_PATTERN = r"^[0-9a-f]{64}$"
COMMIT_PATTERN = r"^[0-9a-f]{40}$"
SAFE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$"
SAFE_KEY_PATTERN = r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$"
SECRET_KEY_PARTS = ("secret", "password", "token", "credential", "api_key", "access_key")


class TrainingModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class Accelerator(StrEnum):
    CPU = "cpu"
    GPU = "gpu"


class TrainingOutcome(StrEnum):
    REJECTED = "REJECTED"
    FAILED = "FAILED"
    INDETERMINATE = "INDETERMINATE"
    CANDIDATE_READY = "CANDIDATE_READY"


class ModelSourceIdentity(TrainingModel):
    provider: Literal["huggingface"] = "huggingface"
    repository_id: str = Field(pattern=SAFE_NAME_PATTERN)
    revision: str = Field(pattern=COMMIT_PATTERN)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    license: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,79}$")
    trust_remote_code: Literal[False] = False
    local_files_only: Literal[True] = True
    use_safetensors: Literal[True] = True


class TrainingDataIdentity(TrainingModel):
    uri: str = Field(pattern=r"^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/[^\s]+$")
    version_id: str = Field(min_length=1, max_length=256)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Classification
    region: Literal["ap-southeast-1"] = "ap-southeast-1"


class TrainingCodeIdentity(TrainingModel):
    git_commit: str = Field(pattern=COMMIT_PATTERN)
    source_sha256: str = Field(pattern=SHA256_PATTERN)


class TrainingContainerIdentity(TrainingModel):
    registry_uri: str = Field(min_length=1, max_length=512)
    image_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")

    @field_validator("registry_uri")
    @classmethod
    def reject_mutable_or_unsafe_registry_uri(cls, value: str) -> str:
        if any(character.isspace() for character in value) or "@sha256:" not in value:
            raise ValueError("container URI must use an immutable digest")
        if value.endswith(":latest"):
            raise ValueError("mutable latest tag is forbidden")
        return value

    @model_validator(mode="after")
    def require_matching_digest(self) -> TrainingContainerIdentity:
        if not self.registry_uri.endswith(f"@{self.image_digest}"):
            raise ValueError("container URI and image digest differ")
        return self


class Hyperparameter(TrainingModel):
    key: str = Field(pattern=SAFE_KEY_PATTERN)
    value: str = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def reject_secrets(self) -> Hyperparameter:
        folded = self.key.casefold()
        if any(part in folded for part in SECRET_KEY_PARTS):
            raise ValueError("secret-bearing hyperparameters are forbidden")
        return self


class CacheEntry(TrainingModel):
    path: str = Field(min_length=1, max_length=512)
    size_bytes: int = Field(ge=0, le=10_737_418_240)
    sha256: str = Field(pattern=SHA256_PATTERN)

    @field_validator("path")
    @classmethod
    def require_safe_relative_path(cls, value: str) -> str:
        parsed = PurePosixPath(value)
        if parsed.is_absolute() or ".." in parsed.parts or "\\" in value or value.startswith("~"):
            raise ValueError("cache paths must be safe relative POSIX paths")
        return value


class TrainingCacheManifest(TrainingModel):
    entries: tuple[CacheEntry, ...] = Field(max_length=10_000)

    @field_validator("entries")
    @classmethod
    def require_sorted_unique_entries(
        cls, values: tuple[CacheEntry, ...]
    ) -> tuple[CacheEntry, ...]:
        paths = tuple(entry.path for entry in values)
        if paths != tuple(sorted(paths)) or len(paths) != len(set(paths)):
            raise ValueError("cache entries must be sorted and unique")
        if sum(entry.size_bytes for entry in values) > 107_374_182_400:
            raise ValueError("cache manifest exceeds the storage ceiling")
        return values


class ResourceRequest(TrainingModel):
    accelerator: Accelerator
    instance_type: str = Field(min_length=1, max_length=80)
    instance_count: Literal[1] = 1
    runtime_seconds: int = Field(gt=0, le=21_600)
    volume_gib: int = Field(gt=0, le=100)


class PeftRequest(TrainingModel):
    enabled: bool = False
    method: Literal["lora"] | None = None
    rank: int | None = Field(default=None, ge=1, le=64)
    target_modules: tuple[str, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def require_complete_lora_contract(self) -> PeftRequest:
        configured = self.method is not None or self.rank is not None or bool(self.target_modules)
        if self.enabled != configured:
            raise ValueError("PEFT fields must be present exactly when PEFT is enabled")
        if self.enabled and self.method != "lora":
            raise ValueError("only the approved LoRA contract is supported")
        if self.target_modules != tuple(sorted(set(self.target_modules))):
            raise ValueError("LoRA target modules must be sorted and unique")
        if any(
            not value or len(value) > 80 or not value.replace("_", "").replace(".", "").isalnum()
            for value in self.target_modules
        ):
            raise ValueError("LoRA target modules must use safe names")
        return self


class TrainingApproval(TrainingModel):
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    requester_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approver_role: Literal["reviewer"] = "reviewer"
    cost_ceiling_usd: Decimal = Field(gt=Decimal("0"))
    peft_approved: bool = False
    decided_at: datetime
    expires_at: datetime

    @field_validator("decided_at", "expires_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("approval timestamps must be UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_independent_unexpired_shape(self) -> TrainingApproval:
        if self.requester_reference_sha256 == self.approver_reference_sha256:
            raise ValueError("requester cannot approve training")
        if self.expires_at <= self.decided_at:
            raise ValueError("approval expiry must follow decision")
        if not self.cost_ceiling_usd.is_finite():
            raise ValueError("cost ceiling must be finite")
        return self


class TrainingRequest(TrainingModel):
    schema_version: Literal["w9-001.training-request.v1"] = "w9-001.training-request.v1"
    request_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    correlation_id: str = Field(pattern=r"^[0-9a-f-]{36}$")
    idempotency_key: str = Field(pattern=SHA256_PATTERN)
    tenant_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    subject_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    authorization_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: Classification
    model: ModelSourceIdentity
    data: TrainingDataIdentity
    code: TrainingCodeIdentity
    container: TrainingContainerIdentity
    hyperparameters: tuple[Hyperparameter, ...] = Field(max_length=128)
    cache: TrainingCacheManifest
    resources: ResourceRequest
    peft: PeftRequest
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    budget_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    approval_reference_sha256: str = Field(pattern=SHA256_PATTERN)
    requested_at: datetime
    deadline_at: datetime

    @field_validator("requested_at", "deadline_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("training timestamps must be UTC")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_consistent_request(self) -> TrainingRequest:
        keys = tuple(item.key for item in self.hyperparameters)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise ValueError("hyperparameters must be sorted and unique")
        if self.data.tenant_reference_sha256 != self.tenant_reference_sha256:
            raise ValueError("data and request tenants differ")
        if self.data.classification != self.classification:
            raise ValueError("data and request classifications differ")
        if self.deadline_at <= self.requested_at:
            raise ValueError("training deadline must follow request time")
        if (self.deadline_at - self.requested_at).total_seconds() > self.resources.runtime_seconds:
            raise ValueError("deadline exceeds the requested runtime")
        return self


class CapabilityEvidence(TrainingModel):
    accelerator: Accelerator
    available: bool
    device_count: int = Field(ge=0, le=64)
    runtime_version: str = Field(min_length=1, max_length=80)


class TrainingResult(TrainingModel):
    schema_version: Literal["w9-001.training-result.v1"] = "w9-001.training-result.v1"
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    outcome: TrainingOutcome
    provider_request_sha256: str = Field(pattern=SHA256_PATTERN)
    candidate_artifact_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)
    safe_reason_code: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,79}$")
    live_execution: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"

    @model_validator(mode="after")
    def require_candidate_only_for_success(self) -> TrainingResult:
        if (self.outcome is TrainingOutcome.CANDIDATE_READY) != (
            self.candidate_artifact_sha256 is not None
        ):
            raise ValueError("candidate identity and outcome differ")
        return self


class CleanupPlan(TrainingModel):
    request_identity_sha256: str = Field(pattern=SHA256_PATTERN)
    exact_job_name: str | None = Field(default=None, max_length=63)
    retain_logs_and_evidence: Literal[True] = True
    delete_shared_resources: Literal[False] = False
    owner_approval_required: Literal[True] = True
    status: Literal["NOT_RUN"] = "NOT_RUN"
