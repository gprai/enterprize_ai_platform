"""Strict, deterministic W6-002 SLI and SLO evaluation contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SLO_SCHEMA_VERSION: Final = "w6-002.slo.v1"
SLO_HARDENING_SCHEMA_VERSION: Final = "w7-001.slo-hardening.v1"
METRIC_NAMESPACE: Final = "EnterpriseAI/Sandbox"
METRIC_DIMENSIONS: Final = ("stage", "operation", "outcome")


class SLOStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - SLO result, not a credential
    FAIL = "FAIL"
    NO_DATA = "NO_DATA"


class EvidenceStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - control result, not a credential
    FAIL = "FAIL"
    NO_DATA = "NO_DATA"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


class MetricSeriesReadiness(BaseModel):
    """Pre-exercise and rollback-window metric evidence without inferred success."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["w7-001.slo-hardening.v1"] = SLO_HARDENING_SCHEMA_VERSION
    namespace: Literal["EnterpriseAI/Sandbox"] = METRIC_NAMESPACE
    dimensions: tuple[Literal["stage", "operation", "outcome"], ...] = METRIC_DIMENSIONS
    pre_exercise_samples: int = Field(ge=0)
    rollback_window_samples: int = Field(ge=0)
    status: EvidenceStatus

    @model_validator(mode="after")
    def preserve_missing_data(self) -> MetricSeriesReadiness:
        missing = self.pre_exercise_samples == 0 or self.rollback_window_samples == 0
        if missing and self.status is not EvidenceStatus.NO_DATA:
            raise ValueError("missing metric samples must remain NO_DATA")
        if not missing and self.status is EvidenceStatus.NO_DATA:
            raise ValueError("NO_DATA requires a missing metric sample window")
        if tuple(self.dimensions) != METRIC_DIMENSIONS:
            raise ValueError("metric dimensions must retain their exact order")
        return self


class AlertOwnershipContract(BaseModel):
    """Stable role and destination references, separate from delivery evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["w7-001.slo-hardening.v1"] = SLO_HARDENING_SCHEMA_VERSION
    owner_reference: str = Field(pattern=r"^role:[a-z0-9][a-z0-9._-]+$")
    backup_owner_reference: str = Field(pattern=r"^role:[a-z0-9][a-z0-9._-]+$")
    destination_reference: str = Field(pattern=r"^external:[a-z0-9][a-z0-9._/-]+$")
    delivery_status: EvidenceStatus
    delivery_evidence_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_delivery_evidence_for_pass(self) -> AlertOwnershipContract:
        if (self.delivery_status is EvidenceStatus.PASS) != (
            self.delivery_evidence_sha256 is not None
        ):
            raise ValueError("PASS requires delivery evidence and non-PASS forbids it")
        return self


class CorrelationContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    request_id_field: Literal["request_id"] = "request_id"
    test_id_field: Literal["test_id"] = "test_id"
    raw_prompt_content_allowed: Literal[False] = False


class SLODefinition(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["w6-002.slo.v1"] = SLO_SCHEMA_VERSION
    slo_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    objective: float = Field(gt=0, le=1)
    window_seconds: int = Field(gt=0)
    minimum_eligible_events: int = Field(gt=0)
    owner: Literal["Gyan Prakash Rai"] = "Gyan Prakash Rai"
    missing_data_status: Literal["NO_DATA"] = "NO_DATA"


class SLIObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    eligible: bool
    good: bool
    timestamp_unix_seconds: int = Field(ge=0)

    @model_validator(mode="after")
    def reject_good_ineligible_observation(self) -> SLIObservation:
        if self.good and not self.eligible:
            raise ValueError("an ineligible observation cannot be marked good")
        return self


class SLOEvaluation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["w6-002.slo.v1"] = SLO_SCHEMA_VERSION
    slo_id: str
    status: SLOStatus
    eligible_events: int = Field(ge=0)
    good_events: int = Field(ge=0)
    bad_events: int = Field(ge=0)
    achieved_ratio: float | None = Field(default=None, ge=0, le=1)
    error_budget_remaining_ratio: float | None = Field(default=None, ge=0, le=1)


def evaluate_slo(
    definition: SLODefinition,
    observations: tuple[SLIObservation, ...],
) -> SLOEvaluation:
    """Evaluate one finite event population without treating missing data as success."""

    eligible = tuple(item for item in observations if item.eligible)
    if len(eligible) < definition.minimum_eligible_events:
        return SLOEvaluation(
            slo_id=definition.slo_id,
            status=SLOStatus.NO_DATA,
            eligible_events=len(eligible),
            good_events=sum(item.good for item in eligible),
            bad_events=sum(not item.good for item in eligible),
        )

    good = sum(item.good for item in eligible)
    bad = len(eligible) - good
    achieved = good / len(eligible)
    allowed_bad_ratio = 1.0 - definition.objective
    consumed_bad_ratio = bad / len(eligible)
    remaining = (
        0.0
        if allowed_bad_ratio == 0
        else max(
            0.0,
            1.0 - consumed_bad_ratio / allowed_bad_ratio,
        )
    )
    return SLOEvaluation(
        slo_id=definition.slo_id,
        status=SLOStatus.PASS if achieved >= definition.objective else SLOStatus.FAIL,
        eligible_events=len(eligible),
        good_events=good,
        bad_events=bad,
        achieved_ratio=achieved,
        error_budget_remaining_ratio=remaining,
    )
