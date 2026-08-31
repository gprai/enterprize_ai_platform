"""Strict immutable contracts for the W4-11 local release rollback drill."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

HexDigest: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
GitSha: TypeAlias = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
ArtifactPath: TypeAlias = Annotated[
    str,
    Field(
        min_length=1,
        max_length=240,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]*$",
    ),
]
ReleaseVersion: TypeAlias = Literal[
    "w4-known-good-v1",
    "w4-synthetic-regression-v1",
]
ExpectedCurrent: TypeAlias = Literal[
    "absent",
    "w4-known-good-v1",
    "w4-synthetic-regression-v1",
]
SmokeGate: TypeAlias = Literal[
    "health",
    "route_profile",
    "release_identity",
    "w3_cited_rag",
    "w3_evaluation",
    "w3_guardrails",
    "w4_agent_failures",
    "api_authentication_authorization",
    "telemetry_correlation_redaction",
    "bounded_api_load",
    "cleanup_zero_unexpected_residue",
]


class StrictReleaseModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class ArtifactFingerprint(StrictReleaseModel):
    path: ArtifactPath
    sha256: HexDigest

    @field_validator("path")
    @classmethod
    def require_safe_posix_path(cls, value: str) -> str:
        relative = PurePosixPath(value)
        if (
            "\\" in value
            or ":" in value
            or relative.is_absolute()
            or relative.as_posix() != value
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("artifact path is unsafe")
        return value


class ReleaseDescriptor(StrictReleaseModel):
    schema_version: Literal["w4-011.release.v1"]
    release_version: ReleaseVersion
    repository_commit_sha: GitSha
    package_version: Literal["0.1.0"]
    composition_algorithm: Literal["sha256-canonical-artifact-set-v1"]
    composition_sha256: HexDigest
    artifact_count: Literal[99]
    artifacts: tuple[ArtifactFingerprint, ...]
    agent_enabled: bool
    regression_profile: Literal["w4-011.agent-route-disabled.v1"] | None = None
    expected_gate: Literal["PASS", "FAIL"]
    expected_safe_error_code: Literal["agent_disabled"] | None = None

    @model_validator(mode="after")
    def require_exact_release_profile(self) -> ReleaseDescriptor:
        paths = tuple(item.path for item in self.artifacts)
        if (
            len(self.artifacts) != self.artifact_count
            or len(paths) != len(set(paths))
            or len({path.casefold() for path in paths}) != len(paths)
        ):
            raise ValueError("release artifact inventory is invalid")
        expected: tuple[bool, str | None, str, str | None]
        if self.release_version == "w4-known-good-v1":
            expected = (True, None, "PASS", None)
        else:
            expected = (
                False,
                "w4-011.agent-route-disabled.v1",
                "FAIL",
                "agent_disabled",
            )
        actual = (
            self.agent_enabled,
            self.regression_profile,
            self.expected_gate,
            self.expected_safe_error_code,
        )
        if actual != expected:
            raise ValueError("release profile differs from owner approval")
        return self


class ActiveReleaseState(StrictReleaseModel):
    schema_version: Literal["w4-011.active.v1"]
    generation: int = Field(ge=1)
    active_release: ReleaseVersion
    descriptor_sha256: HexDigest
    composition_sha256: HexDigest
    agent_route_allowed: bool

    @model_validator(mode="after")
    def require_candidate_latch_closed(self) -> ActiveReleaseState:
        if self.active_release == "w4-synthetic-regression-v1" and self.agent_route_allowed:
            raise ValueError("candidate release cannot enable the agent route")
        return self


class ReleaseActivationOutcome(StrictReleaseModel):
    status: Literal["ACTIVATED", "ALREADY_ACTIVE"]
    active_release: ReleaseVersion
    descriptor_sha256: HexDigest
    generation: int = Field(ge=1)
    agent_route_allowed: bool


class ReleaseValidationResult(StrictReleaseModel):
    status: Literal["VALIDATED"]
    known_good_descriptor_sha256: HexDigest
    regression_descriptor_sha256: HexDigest
    composition_sha256: HexDigest
    artifact_count: Literal[99]


class CandidateProbeResult(StrictReleaseModel):
    status: Literal["EXPECTED_REGRESSION_DETECTED"]
    http_status: Literal[501]
    safe_error_code: Literal["agent_disabled"]
    rag_calls: Literal[0]
    retrieval_calls: Literal[0]
    embedding_calls: Literal[0]
    provider_calls: Literal[0]
    graph_calls: Literal[0]
    approval_calls: Literal[0]
    tool_calls: Literal[0]
    network_activity: Literal[False] = False


class RestoredProbeResult(StrictReleaseModel):
    status: Literal["RESTORED_RELEASE_VERIFIED"]
    health_http_status: Literal[200]
    health_status: Literal["ok"]
    service: Literal["enterprise-ai-platform"]
    environment: Literal["sandbox"]
    agent_route_http_status: Literal[422]
    agent_route_safe_error_code: Literal["api_request_invalid"]
    agent_disabled_observed: Literal[False]
    network_activity: Literal[False] = False


class RegressionReport(StrictReleaseModel):
    schema_version: Literal["w4-011.regression-report.v1"]
    task_id: Literal["W4-ROLLBACK-001"]
    release_version: Literal["w4-synthetic-regression-v1"]
    descriptor_sha256: HexDigest
    composition_sha256: HexDigest
    generation: int = Field(ge=1)
    gate_status: Literal["FAIL"]
    probe: CandidateProbeResult
    agent_route_allowed: Literal[False]


class RollbackReport(StrictReleaseModel):
    schema_version: Literal["w4-011.rollback-report.v1"]
    task_id: Literal["W4-ROLLBACK-001"]
    from_release: Literal["w4-synthetic-regression-v1"]
    restored_release: Literal["w4-known-good-v1"]
    restored_descriptor_sha256: HexDigest
    composition_sha256: HexDigest
    generation: int = Field(ge=1)
    rollback_duration_ms: int = Field(ge=0, le=30_000)
    rollback_status: Literal["PASS"]
    agent_route_allowed: Literal[False]
    network_activity: Literal[False] = False


APPROVED_SMOKE_GATES: tuple[SmokeGate, ...] = (
    "health",
    "route_profile",
    "release_identity",
    "w3_cited_rag",
    "w3_evaluation",
    "w3_guardrails",
    "w4_agent_failures",
    "api_authentication_authorization",
    "telemetry_correlation_redaction",
    "bounded_api_load",
    "cleanup_zero_unexpected_residue",
)


class SmokeReport(StrictReleaseModel):
    schema_version: Literal["w4-011.smoke-report.v1"]
    task_id: Literal["W4-ROLLBACK-001"]
    release_version: Literal["w4-known-good-v1"]
    descriptor_sha256: HexDigest
    composition_sha256: HexDigest
    generation: int = Field(ge=1)
    smoke_duration_ms: int = Field(ge=0)
    passed_gates: tuple[SmokeGate, ...]
    restored_probe: RestoredProbeResult
    smoke_status: Literal["PASS"]
    agent_route_allowed_after_publish: Literal[True]
    network_activity: Literal[False] = False

    @model_validator(mode="after")
    def require_complete_gate_order(self) -> SmokeReport:
        if self.passed_gates != APPROVED_SMOKE_GATES:
            raise ValueError("smoke gate inventory differs from approval")
        return self


class ReleaseLifecycleResult(StrictReleaseModel):
    status: Literal["RESTORED_KNOWN_GOOD"]
    regression: RegressionReport
    rollback: RollbackReport


class CleanlinessResult(StrictReleaseModel):
    status: Literal["CLEAN", "ZERO_RESIDUE"]
    approved_artifact_count: int = Field(ge=0, le=4)
    unexpected_residue_count: Literal[0] = 0
