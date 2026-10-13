"""Strict immutable identities and payloads crossing the serving boundary."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from enterprise_ai_platform.json_contracts import JSONValue, defensive_json_copy


class ServingModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class ModelClass(StrEnum):
    FOUNDATION = "foundation"
    CUSTOM = "custom"
    STRUCTURED = "structured"


class ServingProvider(StrEnum):
    BEDROCK = "bedrock"
    SAGEMAKER_REALTIME = "sagemaker_realtime"
    EKS = "eks"


class ArtifactApprovalState(StrEnum):
    APPROVED = "approved"
    PENDING = "pending"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class ArtifactIdentity(ServingModel):
    """Canonical identity for an approved or conditionally eligible artifact."""

    schema_version: Literal["w8-001.artifact.v1"] = "w8-001.artifact.v1"
    model_class: ModelClass
    artifact_name: str = Field(min_length=1, max_length=200)
    artifact_version: str = Field(min_length=1, max_length=100)
    artifact_digest_algorithm: Literal["sha256"] = "sha256"
    artifact_digest: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    source_uri: str = Field(min_length=1, max_length=2000)
    license: str = Field(min_length=1, max_length=200)
    approval_state: ArtifactApprovalState
    approval_reference: str = Field(min_length=1, max_length=200)
    tenant_scope: str = Field(min_length=1, max_length=128)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    processing_region: Literal["ap-southeast-1", "Global Cross-Region"]
    training_identity_reference: str = Field(min_length=1, max_length=200)
    inference_identity_reference: str = Field(min_length=1, max_length=200)
    supersedes: str | None = Field(default=None, max_length=64)

    @field_validator("source_uri")
    @classmethod
    def require_non_secret_source_uri(cls, value: str) -> str:
        if any(token in value.casefold() for token in ("password", "secret", "credential")):
            raise ValueError("source_uri must not contain credential-like material")
        return value

    def canonical_bytes(self) -> bytes:
        payload = self.model_dump(mode="json")
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def canonical_digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


class ServingRequest(ServingModel):
    request_id: str = Field(min_length=1, max_length=128)
    artifact: ArtifactIdentity
    tenant_id: str = Field(min_length=1, max_length=128)
    classification: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
    authorized: bool
    payload: dict[str, JSONValue]

    @field_validator("payload", mode="before")
    @classmethod
    def detach_payload(cls, value: Any) -> Any:
        return defensive_json_copy(value)


class ServingResponse(ServingModel):
    request_id: str = Field(min_length=1, max_length=128)
    provider: ServingProvider
    artifact_digest: str = Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$")
    output: JSONValue
