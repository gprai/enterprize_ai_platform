"""Governed W11-001 AI SLI, SLO, burn-rate, and release decisions."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal, cast

import yaml  # type: ignore[import-untyped]
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

AI_RELIABILITY_SCHEMA_VERSION: Final = "w11-001.ai-reliability.v1"
AI_RELIABILITY_BATCH_SCHEMA_VERSION: Final = "w11-001.ai-reliability-batch.v1"
DEFAULT_AI_RELIABILITY_POLICY_PATH: Final = Path("configs/observability/slo.yaml")
AI_RELIABILITY_METRIC_NAMES: Final = {
    "decision": "enterprise_ai.ai.reliability.decision",
    "error_budget_remaining_ratio": ("enterprise_ai.ai.reliability.error_budget_remaining_ratio"),
    "observed_value": "enterprise_ai.ai.reliability.observed_value",
}

AI_RELIABILITY_SLI_ORDER: Final = (
    "availability",
    "api_latency_p95",
    "api_latency_p99",
    "retrieval_latency_p99",
    "answer_correctness",
    "grounded_answer_rate",
    "citation_coverage",
    "retrieval_relevance",
    "correct_abstention_rate",
    "unauthorized_retrieval_rate",
    "safety_violation_rate",
    "pii_leakage_rate",
    "ingestion_freshness_hours",
    "retrieval_dependency_availability",
    "model_dependency_availability",
    "tokens_per_successful_query",
    "cost_per_successful_query_usd",
)

_EXPECTED_THRESHOLDS: Final = {
    "availability": Decimal("0.999"),
    "api_latency_p95": Decimal("4"),
    "api_latency_p99": Decimal("10"),
    "retrieval_latency_p99": Decimal("0.75"),
    "answer_correctness": Decimal("0.95"),
    "grounded_answer_rate": Decimal("0.95"),
    "citation_coverage": Decimal("1.0"),
    "retrieval_relevance": Decimal("0.85"),
    "correct_abstention_rate": Decimal("0.95"),
    "unauthorized_retrieval_rate": Decimal("0"),
    "safety_violation_rate": Decimal("0"),
    "pii_leakage_rate": Decimal("0"),
    "ingestion_freshness_hours": Decimal("24"),
    "retrieval_dependency_availability": Decimal("0.999"),
    "model_dependency_availability": Decimal("0.999"),
    "tokens_per_successful_query": Decimal("16896"),
    "cost_per_successful_query_usd": Decimal("0.01"),
}


class DecisionStatus(StrEnum):
    PASS = "PASS"  # noqa: S105 - governance result, not a credential
    FAIL = "FAIL"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


class CollectionStatus(StrEnum):
    MEASURED = "MEASURED"
    NOT_RUN = "NOT RUN"
    INDETERMINATE = "INDETERMINATE"


class ThresholdDirection(StrEnum):
    MINIMUM = "minimum"
    MAXIMUM = "maximum"


class BurnPolicy(StrEnum):
    PAIRED_WINDOWS = "paired_windows"
    IMMEDIATE = "immediate"
    RELEASE_GATE = "release_gate"


class ReleaseAction(StrEnum):
    RELEASE_ALLOWED = "release_allowed"
    RELEASE_BLOCKED = "release_blocked"
    RELEASE_FROZEN_ROLLBACK_REVIEW = "release_frozen_rollback_review"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, validate_default=True)


def _require_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        raise ValueError("timestamp must be UTC-aware")
    return value.astimezone(UTC)


class BurnRateTier(_StrictModel):
    factor: Decimal = Field(gt=0)
    short_window: Literal["5m", "30m"]
    long_window: Literal["1h", "6h"]
    minimum_short_window_events: Literal[20] = 20


class BurnRateContract(_StrictModel):
    fast: BurnRateTier
    slow: BurnRateTier

    @model_validator(mode="after")
    def require_exact_tiers(self) -> BurnRateContract:
        if self.fast != BurnRateTier(factor=Decimal("14.4"), short_window="5m", long_window="1h"):
            raise ValueError("fast burn contract differs from the owner-approved value")
        if self.slow != BurnRateTier(factor=Decimal("6"), short_window="30m", long_window="6h"):
            raise ValueError("slow burn contract differs from the owner-approved value")
        return self


class MetricDimensionContract(_StrictModel):
    allowed: tuple[Literal["stage", "operation", "outcome", "dependency", "sli_id"], ...]
    prohibited: tuple[
        Literal[
            "request_id",
            "test_id",
            "tenant_id",
            "user_id",
            "document_id",
            "prompt",
            "response",
        ],
        ...,
    ]
    correlation_field: Literal["request_id"] = "request_id"
    correlation_is_metric_dimension: Literal[False] = False
    raw_prompt_content_allowed: Literal[False] = False
    raw_response_content_allowed: Literal[False] = False

    @model_validator(mode="after")
    def require_exact_dimension_contract(self) -> MetricDimensionContract:
        if self.allowed != ("stage", "operation", "outcome", "dependency", "sli_id"):
            raise ValueError("stable metric dimensions differ from the bounded allowlist")
        if self.prohibited != (
            "request_id",
            "test_id",
            "tenant_id",
            "user_id",
            "document_id",
            "prompt",
            "response",
        ):
            raise ValueError("prohibited metric dimensions differ")
        return self


class EscalationContract(_StrictModel):
    owner_reference: Literal["role:platform-observability-primary"]
    backup_owner_reference: Literal["role:platform-observability-backup"]
    task_owner_reference: Literal["role:enterprise-ai-owner"]
    destination_reference: Literal["external:owner-approved-alert-destination"]
    delivery_status: Literal["NOT RUN"] = "NOT RUN"
    critical_primary_ack_minutes: Literal[5] = 5
    critical_backup_minutes: Literal[10] = 10
    critical_owner_minutes: Literal[15] = 15
    warning_primary_ack_minutes: Literal[30] = 30
    warning_backup_minutes: Literal[60] = 60


class MaintenanceContract(_StrictModel):
    standing_exclusions_allowed: Literal[False] = False
    one_off_utc_only: Literal[True] = True
    maximum_duration_minutes: Literal[120] = 120
    suppressible_sli_ids: tuple[str, ...]
    never_suppress_sli_ids: tuple[str, ...]

    @model_validator(mode="after")
    def require_security_boundaries(self) -> MaintenanceContract:
        required = (
            "unauthorized_retrieval_rate",
            "safety_violation_rate",
            "pii_leakage_rate",
        )
        if self.never_suppress_sli_ids != required:
            raise ValueError("authorization, safety, and PII SLIs can never be suppressed")
        if set(self.suppressible_sli_ids) & set(required):
            raise ValueError("maintenance suppression includes a protected SLI")
        if len(self.suppressible_sli_ids) != len(set(self.suppressible_sli_ids)):
            raise ValueError("maintenance suppression SLIs must be unique")
        return self


class DecisionContract(_StrictModel):
    pass_action: Literal["release_allowed"] = "release_allowed"  # noqa: S105 - policy action, not a credential
    fail_action: Literal["release_frozen_rollback_review"] = "release_frozen_rollback_review"
    not_run_action: Literal["release_blocked"] = "release_blocked"
    indeterminate_action: Literal["release_blocked"] = "release_blocked"
    automatic_rollback_allowed: Literal[False] = False
    rollback_requires_reviewed_policy_change: Literal[True] = True
    gap_07_status: Literal["OPEN_UNTIL_OWNER_EVIDENCE"] = "OPEN_UNTIL_OWNER_EVIDENCE"
    gap_10_status: Literal["OPEN_UNTIL_OWNER_EVIDENCE"] = "OPEN_UNTIL_OWNER_EVIDENCE"
    gap_14_status: Literal["OPEN_UNTIL_OWNER_EVIDENCE"] = "OPEN_UNTIL_OWNER_EVIDENCE"


class SLIContract(_StrictModel):
    sli_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    direction: ThresholdDirection
    unit: Literal["ratio", "seconds", "hours", "tokens", "usd"]
    population: str = Field(pattern=r"^[a-z][a-z0-9_]{1,95}$")
    denominator: str = Field(pattern=r"^[a-z][a-z0-9_]{1,95}$")
    window: Literal["30d"] = "30d"
    minimum_samples: int = Field(gt=0)
    data_source: str = Field(pattern=r"^[a-zA-Z0-9_.:-]{3,160}$")
    threshold: Decimal = Field(ge=0)
    burn_policy: BurnPolicy
    missing_data_status: Literal["INDETERMINATE"] = "INDETERMINATE"

    @field_validator("threshold")
    @classmethod
    def require_finite_threshold(cls, value: Decimal) -> Decimal:
        if not value.is_finite():
            raise ValueError("SLI threshold must be finite")
        return value


class AIReliabilityPolicy(_StrictModel):
    schema_version: Literal["w11-001.ai-reliability.v1"] = AI_RELIABILITY_SCHEMA_VERSION
    prompt_id: Literal["W11-001"] = "W11-001"
    feature_id: Literal["OBS-001"] = "OBS-001"
    classification: Literal["source-contract-not-live-evidence"]
    status_values: tuple[Literal["PASS", "FAIL", "NOT RUN", "INDETERMINATE"], ...]
    metric_dimensions: MetricDimensionContract
    burn_rate: BurnRateContract
    maintenance: MaintenanceContract
    escalation: EscalationContract
    decision: DecisionContract
    slis: tuple[SLIContract, ...]

    @model_validator(mode="after")
    def require_exact_contract(self) -> AIReliabilityPolicy:
        if self.status_values != ("PASS", "FAIL", "NOT RUN", "INDETERMINATE"):
            raise ValueError("decision status order differs")
        ids = tuple(item.sli_id for item in self.slis)
        if ids != AI_RELIABILITY_SLI_ORDER:
            raise ValueError("AI SLI inventory or ordering differs")
        thresholds = {item.sli_id: item.threshold for item in self.slis}
        if thresholds != _EXPECTED_THRESHOLDS:
            raise ValueError("AI SLI thresholds differ")
        return self


class SLIEvidence(_StrictModel):
    schema_version: Literal["w11-001.ai-reliability.v1"] = AI_RELIABILITY_SCHEMA_VERSION
    sli_id: str = Field(pattern=r"^[a-z][a-z0-9_]{1,63}$")
    collection_status: CollectionStatus
    sample_count: int = Field(ge=0)
    observed_value: Decimal | None = Field(default=None, ge=0)
    observed_at: datetime
    source_identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    correlated_request_count: int = Field(default=0, ge=0)
    correlation_digest_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    reason: str | None = Field(default=None, min_length=1, max_length=240)

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @field_validator("observed_value")
    @classmethod
    def require_finite_value(cls, value: Decimal | None) -> Decimal | None:
        if value is not None and not value.is_finite():
            raise ValueError("observed SLI value must be finite")
        return value

    @model_validator(mode="after")
    def require_collection_evidence(self) -> SLIEvidence:
        if self.collection_status is CollectionStatus.MEASURED:
            if self.sample_count == 0 or self.observed_value is None:
                raise ValueError("MEASURED evidence requires samples and a value")
            if self.source_identity_sha256 is None:
                raise ValueError("MEASURED evidence requires a source identity")
            if (self.correlated_request_count > 0) != (self.correlation_digest_sha256 is not None):
                raise ValueError("correlated requests require one content-free digest")
        elif self.observed_value is not None or self.source_identity_sha256 is not None:
            raise ValueError("unmeasured evidence cannot carry a measured value or identity")
        elif self.correlated_request_count != 0 or self.correlation_digest_sha256 is not None:
            raise ValueError("unmeasured evidence cannot carry request correlation")
        if self.collection_status is not CollectionStatus.MEASURED and self.reason is None:
            raise ValueError("unmeasured evidence requires a reason")
        return self


class SLIEvaluation(_StrictModel):
    schema_version: Literal["w11-001.ai-reliability.v1"] = AI_RELIABILITY_SCHEMA_VERSION
    sli_id: str
    status: DecisionStatus
    sample_count: int = Field(ge=0)
    observed_value: Decimal | None = Field(default=None, ge=0)
    threshold: Decimal = Field(ge=0)
    error_budget_remaining_ratio: Decimal | None = Field(default=None, ge=0, le=1)
    reason: str


class BurnRateEvidence(_StrictModel):
    tier: Literal["fast", "slow"]
    collection_status: CollectionStatus
    short_window_burn_factor: Decimal | None = Field(default=None, ge=0)
    long_window_burn_factor: Decimal | None = Field(default=None, ge=0)
    short_window_events: int = Field(ge=0)
    observed_at: datetime

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def require_burn_evidence(self) -> BurnRateEvidence:
        measured = self.collection_status is CollectionStatus.MEASURED
        has_factors = (
            self.short_window_burn_factor is not None and self.long_window_burn_factor is not None
        )
        if measured != has_factors:
            raise ValueError("MEASURED burn evidence requires both window factors")
        return self


class BurnRateEvaluation(_StrictModel):
    tier: Literal["fast", "slow"]
    status: DecisionStatus
    severity: Literal["critical", "warning"]
    threshold_factor: Decimal = Field(gt=0)
    reason: str


class EvaluationBatch(_StrictModel):
    schema_version: Literal["w11-001.ai-reliability-batch.v1"] = AI_RELIABILITY_BATCH_SCHEMA_VERSION
    sli_evidence: tuple[SLIEvidence, ...]
    burn_evidence: tuple[BurnRateEvidence, ...] = ()


class ReleaseDecision(_StrictModel):
    schema_version: Literal["w11-001.ai-reliability.v1"] = AI_RELIABILITY_SCHEMA_VERSION
    status: DecisionStatus
    action: ReleaseAction
    release_allowed: bool
    automatic_rollback: Literal[False] = False
    rollback_review_required: bool
    reasons: tuple[str, ...]
    gaps_remaining_open: tuple[Literal["GAP-07", "GAP-10", "GAP-14"], ...] = (
        "GAP-07",
        "GAP-10",
        "GAP-14",
    )


class MaintenanceWindow(_StrictModel):
    window_id: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{1,63}$")
    starts_at: datetime
    ends_at: datetime
    owner_approval_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    suppressed_sli_ids: tuple[str, ...]

    @field_validator("starts_at", "ends_at")
    @classmethod
    def validate_times(cls, value: datetime) -> datetime:
        return _require_utc(value)

    @model_validator(mode="after")
    def require_bounded_window(self) -> MaintenanceWindow:
        if self.ends_at <= self.starts_at:
            raise ValueError("maintenance window ordering is invalid")
        if self.ends_at - self.starts_at > timedelta(minutes=120):
            raise ValueError("maintenance window exceeds two hours")
        if len(self.suppressed_sli_ids) != len(set(self.suppressed_sli_ids)):
            raise ValueError("maintenance suppression SLIs must be unique")
        return self


class _UniqueKeyLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _construct_unique_mapping(
    loader: _UniqueKeyLoader,
    node: Any,
    deep: bool = False,
) -> dict[object, object]:
    result: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate YAML key: {key!r}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def load_ai_reliability_policy(
    path: Path = DEFAULT_AI_RELIABILITY_POLICY_PATH,
) -> AIReliabilityPolicy:
    """Load the additive W11 section without reinterpreting the W6/W10 schemas."""

    try:
        payload = path.read_bytes()
        if not payload or len(payload) > 131_072 or payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise ValueError("AI reliability policy encoding or size is invalid")
        text = payload.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise ValueError("YAML aliases are not permitted")
        loader = _UniqueKeyLoader(text)
        try:
            raw = loader.get_single_data()
        finally:
            loader.dispose()
        if not isinstance(raw, dict) or not isinstance(raw.get("ai_reliability"), dict):
            raise ValueError("AI reliability policy section must be a mapping")
        return AIReliabilityPolicy.model_validate(
            cast(dict[str, object], raw["ai_reliability"]),
            strict=False,
        )
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as error:
        raise ValueError("invalid AI reliability policy") from error


def evaluate_sli(contract: SLIContract, evidence: SLIEvidence) -> SLIEvaluation:
    """Evaluate one exact SLI without converting absent or weak evidence to PASS."""

    if evidence.sli_id != contract.sli_id:
        raise ValueError("SLI evidence identity does not match its contract")

    def result(
        status: DecisionStatus,
        reason: str,
        error_budget_remaining_ratio: Decimal | None = None,
    ) -> SLIEvaluation:
        return SLIEvaluation(
            sli_id=contract.sli_id,
            status=status,
            sample_count=evidence.sample_count,
            observed_value=evidence.observed_value,
            threshold=contract.threshold,
            error_budget_remaining_ratio=error_budget_remaining_ratio,
            reason=reason,
        )

    if evidence.collection_status is CollectionStatus.NOT_RUN:
        return result(DecisionStatus.NOT_RUN, evidence.reason or "measurement was not run")
    if evidence.collection_status is CollectionStatus.INDETERMINATE:
        return result(
            DecisionStatus.INDETERMINATE,
            evidence.reason or "measurement is indeterminate",
        )
    if evidence.sample_count < contract.minimum_samples:
        return result(
            DecisionStatus.INDETERMINATE,
            (f"sample count {evidence.sample_count} is below minimum {contract.minimum_samples}"),
        )

    value = cast(Decimal, evidence.observed_value)
    passed = (
        value >= contract.threshold
        if contract.direction is ThresholdDirection.MINIMUM
        else value <= contract.threshold
    )
    remaining: Decimal | None = None
    if contract.unit == "ratio":
        if contract.direction is ThresholdDirection.MINIMUM:
            allowed_bad = Decimal(1) - contract.threshold
            actual_bad = Decimal(1) - value
        else:
            allowed_bad = contract.threshold
            actual_bad = value
        if allowed_bad > 0:
            remaining = max(Decimal(0), Decimal(1) - (actual_bad / allowed_bad))
        elif actual_bad == 0:
            remaining = Decimal(1)
        else:
            remaining = Decimal(0)
    return result(
        DecisionStatus.PASS if passed else DecisionStatus.FAIL,
        "threshold met" if passed else "threshold breached",
        remaining,
    )


def evaluate_burn_rate(
    policy: AIReliabilityPolicy,
    evidence: BurnRateEvidence,
) -> BurnRateEvaluation:
    """Require both paired windows and a minimum event population."""

    tier = policy.burn_rate.fast if evidence.tier == "fast" else policy.burn_rate.slow
    severity: Literal["critical", "warning"] = "critical" if evidence.tier == "fast" else "warning"
    if evidence.collection_status is CollectionStatus.NOT_RUN:
        return BurnRateEvaluation(
            tier=evidence.tier,
            status=DecisionStatus.NOT_RUN,
            severity=severity,
            threshold_factor=tier.factor,
            reason="burn-rate measurement was not run",
        )
    if evidence.collection_status is CollectionStatus.INDETERMINATE:
        return BurnRateEvaluation(
            tier=evidence.tier,
            status=DecisionStatus.INDETERMINATE,
            severity=severity,
            threshold_factor=tier.factor,
            reason="burn-rate measurement is indeterminate",
        )
    if evidence.short_window_events < tier.minimum_short_window_events:
        return BurnRateEvaluation(
            tier=evidence.tier,
            status=DecisionStatus.INDETERMINATE,
            severity=severity,
            threshold_factor=tier.factor,
            reason="burn-rate short window has insufficient samples",
        )
    breached = (
        cast(Decimal, evidence.short_window_burn_factor) >= tier.factor
        and cast(Decimal, evidence.long_window_burn_factor) >= tier.factor
    )
    return BurnRateEvaluation(
        tier=evidence.tier,
        status=DecisionStatus.FAIL if breached else DecisionStatus.PASS,
        severity=severity,
        threshold_factor=tier.factor,
        reason="paired burn-rate threshold breached" if breached else "paired windows healthy",
    )


def decide_release(
    policy: AIReliabilityPolicy,
    sli_evaluations: tuple[SLIEvaluation, ...],
    burn_evaluations: tuple[BurnRateEvaluation, ...] = (),
) -> ReleaseDecision:
    """Apply fail-closed release policy; never trigger an automatic rollback."""

    by_id = {item.sli_id: item for item in sli_evaluations}
    if len(by_id) != len(sli_evaluations):
        raise ValueError("SLI evaluations must have unique identities")
    expected_sli_ids = tuple(item.sli_id for item in policy.slis)
    missing = tuple(sli_id for sli_id in expected_sli_ids if sli_id not in by_id)
    unexpected = tuple(sli_id for sli_id in by_id if sli_id not in expected_sli_ids)
    burn_by_tier = {item.tier: item for item in burn_evaluations}
    if len(burn_by_tier) != len(burn_evaluations):
        raise ValueError("burn-rate evaluations must have unique tiers")
    missing_burn = tuple(tier for tier in ("fast", "slow") if tier not in burn_by_tier)
    statuses = tuple(item.status for item in sli_evaluations) + tuple(
        item.status for item in burn_evaluations
    )
    reasons = [
        f"{item.sli_id}: {item.reason}"
        for item in sli_evaluations
        if item.status is not DecisionStatus.PASS
    ]
    reasons.extend(
        f"burn.{item.tier}: {item.reason}"
        for item in burn_evaluations
        if item.status is not DecisionStatus.PASS
    )
    if DecisionStatus.FAIL in statuses:
        status = DecisionStatus.FAIL
    elif missing or unexpected or missing_burn:
        reasons.append(f"missing={','.join(missing) or 'none'}")
        reasons.append(f"unexpected={','.join(unexpected) or 'none'}")
        reasons.append(f"missing_burn={','.join(missing_burn) or 'none'}")
        status = DecisionStatus.INDETERMINATE
    elif DecisionStatus.INDETERMINATE in statuses:
        status = DecisionStatus.INDETERMINATE
    elif DecisionStatus.NOT_RUN in statuses:
        status = DecisionStatus.NOT_RUN
    else:
        status = DecisionStatus.PASS

    if status is DecisionStatus.PASS:
        action = ReleaseAction.RELEASE_ALLOWED
    elif status is DecisionStatus.FAIL:
        action = ReleaseAction.RELEASE_FROZEN_ROLLBACK_REVIEW
    else:
        action = ReleaseAction.RELEASE_BLOCKED
    return ReleaseDecision(
        status=status,
        action=action,
        release_allowed=status is DecisionStatus.PASS,
        rollback_review_required=status is DecisionStatus.FAIL,
        reasons=tuple(reasons) if reasons else ("all governed objectives passed",),
    )


def evaluate_batch(
    policy: AIReliabilityPolicy,
    batch: EvaluationBatch,
) -> tuple[tuple[SLIEvaluation, ...], tuple[BurnRateEvaluation, ...], ReleaseDecision]:
    """Evaluate a bounded external batch with no network calls or file writes."""

    contracts = {item.sli_id: item for item in policy.slis}
    evaluations = tuple(
        evaluate_sli(contracts[item.sli_id], item)
        if item.sli_id in contracts
        else SLIEvaluation(
            sli_id=item.sli_id,
            status=DecisionStatus.INDETERMINATE,
            sample_count=item.sample_count,
            observed_value=item.observed_value,
            threshold=Decimal(0),
            reason="unexpected SLI identity",
        )
        for item in batch.sli_evidence
    )
    burn = tuple(evaluate_burn_rate(policy, item) for item in batch.burn_evidence)
    return evaluations, burn, decide_release(policy, evaluations, burn)


def maintenance_suppresses(
    policy: AIReliabilityPolicy,
    window: MaintenanceWindow,
    *,
    sli_id: str,
    observed_at: datetime,
) -> bool:
    """Return bounded one-off suppression; security/safety/PII always remain active."""

    current = _require_utc(observed_at)
    requested = set(window.suppressed_sli_ids)
    if requested - set(policy.maintenance.suppressible_sli_ids):
        raise ValueError("maintenance window contains an unsuppressible SLI")
    if requested & set(policy.maintenance.never_suppress_sli_ids):
        raise ValueError("maintenance window contains a protected SLI")
    return sli_id in requested and window.starts_at <= current < window.ends_at
