"""Strict, deterministic W6-002 SLI and SLO evaluation contracts."""

from __future__ import annotations

from enum import StrEnum
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

SLO_SCHEMA_VERSION: Final = "w6-002.slo.v1"


class SLOStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - SLO result, not a credential
    FAIL = "FAIL"
    NO_DATA = "NO_DATA"


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
