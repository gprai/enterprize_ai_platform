"""Strict W10-004 AI-operations policy, decisions, and observations."""

from __future__ import annotations

import math
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Literal, Protocol, cast

import yaml  # type: ignore[import-untyped]
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

AI_OPERATIONS_SCHEMA_VERSION: Final = "w10-004.ai-operations.v1"
AI_OPERATIONS_POLICY_SCHEMA_VERSION: Final = "w10-004.ai-operations-policy.v1"
DEFAULT_AI_OPERATIONS_POLICY_PATH: Final = Path("configs/observability/ai-operations-policy.yaml")


class EvaluationBindingStatus(StrEnum):
    EXACT_MATCH = "exact_match"
    ABSENT = "absent"
    MISMATCH = "mismatch"


class DependencyKind(StrEnum):
    RETRIEVAL = "retrieval"
    MODEL = "model"


class AdmissionReason(StrEnum):
    ADMITTED = "admitted"
    RATE_LIMITED = "rate_limited"
    BACKPRESSURE = "backpressure"
    CIRCUIT_OPEN = "circuit_open"
    DRAINING = "draining"


class CostGuardReason(StrEnum):
    ALLOWED = "allowed"
    DISABLED = "disabled"
    PRICING_MISSING = "pricing_missing"
    PRICING_STALE = "pricing_stale"
    PROVIDER_NOT_APPROVED = "provider_not_approved"
    PROJECTED_COST_EXCEEDED = "projected_cost_exceeded"


class AIOperationsSignal(StrEnum):
    REQUEST_COST = "request_cost"
    RETRIEVAL_QUALITY = "retrieval_quality"
    GROUNDEDNESS = "groundedness"
    CITATION_COVERAGE = "citation_coverage"
    ABSTENTION = "abstention"
    DEPENDENCY_AVAILABILITY = "dependency_availability"
    ADMISSION_DECISION = "admission_decision"
    QUEUE_DEPTH = "queue_depth"
    CONFIGURATION_DRIFT = "configuration_drift"
    COST_GUARD_DECISION = "cost_guard_decision"


AI_OPERATIONS_METRIC_NAMES: Final = {
    AIOperationsSignal.REQUEST_COST: "enterprise_ai.ai.request.cost_usd",
    AIOperationsSignal.RETRIEVAL_QUALITY: "enterprise_ai.ai.retrieval.quality",
    AIOperationsSignal.GROUNDEDNESS: "enterprise_ai.ai.groundedness",
    AIOperationsSignal.CITATION_COVERAGE: "enterprise_ai.ai.citation.coverage",
    AIOperationsSignal.ABSTENTION: "enterprise_ai.ai.abstentions",
    AIOperationsSignal.DEPENDENCY_AVAILABILITY: ("enterprise_ai.ai.dependency.availability"),
    AIOperationsSignal.ADMISSION_DECISION: "enterprise_ai.ai.admission.decisions",
    AIOperationsSignal.QUEUE_DEPTH: "enterprise_ai.ai.queue.depth",
    AIOperationsSignal.CONFIGURATION_DRIFT: "enterprise_ai.ai.configuration.drift",
    AIOperationsSignal.COST_GUARD_DECISION: "enterprise_ai.ai.cost_guard.decisions",
}


class _StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_default=True,
    )


class _CostPolicy(_StrictModel):
    cost_per_successful_request_ceiling_usd: Decimal = Field(gt=0, le=Decimal("0.01"))
    price_maximum_age_hours: Literal[24] = 24
    maximum_input_tokens: Literal[16_384] = 16_384
    maximum_output_tokens: Literal[512] = 512

    @field_validator("cost_per_successful_request_ceiling_usd")
    @classmethod
    def require_exact_ceiling(cls, value: Decimal) -> Decimal:
        if value != Decimal("0.01"):
            raise ValueError("cost ceiling must match the owner-approved value")
        return value


class _QualityPolicy(_StrictModel):
    retrieval_quality_floor: Decimal = Field(ge=0, le=1)
    groundedness_proxy_floor: Decimal = Field(default=Decimal("1.0"), ge=0, le=1)
    citation_coverage_floor: Decimal = Field(default=Decimal("1.0"), ge=0, le=1)

    @field_validator("groundedness_proxy_floor", "citation_coverage_floor")
    @classmethod
    def require_exact_complete_ratio(cls, value: Decimal) -> Decimal:
        if value != Decimal("1.0"):
            raise ValueError("groundedness and citation floors must be complete")
        return value


class _PrivacyPolicy(_StrictModel):
    raw_prompt_capture: Literal[False] = False
    raw_response_capture: Literal[False] = False
    encryption_in_transit_required: Literal[True] = True
    access_control: Literal["existing_observability_rbac"] = "existing_observability_rbac"
    stable_metric_dimensions: tuple[
        Literal[
            "signal",
            "provider",
            "dependency",
            "outcome",
            "reason",
            "evaluation_status",
        ],
        ...,
    ]

    @field_validator("stable_metric_dimensions")
    @classmethod
    def require_exact_dimensions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        expected = (
            "signal",
            "provider",
            "dependency",
            "outcome",
            "reason",
            "evaluation_status",
        )
        if value != expected:
            raise ValueError("AI metric dimensions differ from the bounded allowlist")
        return value


class _RetentionPolicy(_StrictModel):
    operational_telemetry_days: Literal[14] = 14
    approved_evaluation_evidence_days: Literal[180] = 180


class _ResiliencePolicy(_StrictModel):
    retry_attempts: Literal[0] = 0
    query_queue_capacity: Literal[0] = 0
    safe_degraded_mode: Literal[True] = True


class AIOperationsPolicy(_StrictModel):
    schema_version: Literal["w10-004.ai-operations-policy.v1"] = AI_OPERATIONS_POLICY_SCHEMA_VERSION
    prompt_id: Literal["W10-004"] = "W10-004"
    feature_id: Literal["OBS-001"] = "OBS-001"
    enabled_by_default: Literal[False] = False
    approved_providers: tuple[Literal["bedrock"], ...] = ("bedrock",)
    cost: _CostPolicy
    quality: _QualityPolicy
    privacy: _PrivacyPolicy
    retention: _RetentionPolicy
    resilience: _ResiliencePolicy
    live_execution: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"

    @model_validator(mode="after")
    def require_exact_provider_contract(self) -> AIOperationsPolicy:
        if self.approved_providers != ("bedrock",):
            raise ValueError("only the approved Bedrock provider is permitted")
        return self


class PricingSnapshot(_StrictModel):
    observed_at: datetime
    input_token_rate_usd_per_million: Decimal = Field(ge=0)
    output_token_rate_usd_per_million: Decimal = Field(ge=0)

    @field_validator("observed_at")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("pricing observation must be UTC")
        return value.astimezone(UTC)


class RuntimeIdentityBinding(_StrictModel):
    model_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    prompt_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    embedding_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retrieval_config_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluation_config_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    evaluation_status: EvaluationBindingStatus

    @model_validator(mode="after")
    def require_status_consistency(self) -> RuntimeIdentityBinding:
        if self.evaluation_status is EvaluationBindingStatus.ABSENT:
            if self.evaluation_config_sha256 is not None:
                raise ValueError("absent evaluation binding cannot carry an identity")
        elif self.evaluation_config_sha256 is None:
            raise ValueError("present evaluation status requires an identity")
        return self


class AIOperationsObservation(_StrictModel):
    schema_version: Literal["w10-004.ai-operations.v1"] = AI_OPERATIONS_SCHEMA_VERSION
    signal: AIOperationsSignal
    value: float = Field(ge=0)
    provider: Literal["bedrock", "fake"] | None = None
    dependency: DependencyKind | None = None
    outcome: Literal["success", "degraded", "denied", "abstained"] | None = None
    admission_reason: AdmissionReason | None = None
    cost_guard_reason: CostGuardReason | None = None
    evaluation_status: EvaluationBindingStatus | None = None

    @field_validator("value")
    @classmethod
    def require_finite_value(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("AI operations value must be finite")
        return value

    def metric_attributes(self) -> dict[str, str]:
        values = self.model_dump(
            mode="json",
            exclude_none=True,
            exclude={"schema_version", "value"},
        )
        return {key: str(value) for key, value in values.items()}


class AIOperationsDecision(_StrictModel):
    allowed: bool
    reason: CostGuardReason
    projected_cost_usd: Decimal | None = Field(default=None, ge=0)
    safe_degraded: bool


class _AIOperationsRecorder(Protocol):
    def record_ai_operation(self, observation: AIOperationsObservation) -> None: ...


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


def load_ai_operations_policy(
    path: Path = DEFAULT_AI_OPERATIONS_POLICY_PATH,
) -> AIOperationsPolicy:
    """Load the bounded, duplicate-safe AI-operations policy."""

    try:
        payload = path.read_bytes()
        if not payload or len(payload) > 65_536 or payload.startswith((b"\xff\xfe", b"\xfe\xff")):
            raise ValueError("AI operations policy encoding or size is invalid")
        text = payload.decode("utf-8", errors="strict")
        if "&" in text or "*" in text:
            raise ValueError("YAML aliases are not permitted")
        loader = _UniqueKeyLoader(text)
        try:
            raw = loader.get_single_data()
        finally:
            loader.dispose()
        if not isinstance(raw, dict):
            raise ValueError("AI operations policy must be a mapping")
        return AIOperationsPolicy.model_validate(cast(dict[str, object], raw), strict=False)
    except (OSError, UnicodeError, yaml.YAMLError, ValidationError) as error:
        raise ValueError("invalid AI operations policy") from error


def preflight_provider_call(
    policy: AIOperationsPolicy,
    *,
    enabled: bool,
    provider: str,
    pricing: PricingSnapshot | None,
    observed_at: datetime,
    maximum_input_tokens: int,
    maximum_output_tokens: int,
) -> AIOperationsDecision:
    """Fail closed before a paid provider call when W10-004 is enabled."""

    if not enabled:
        return AIOperationsDecision(
            allowed=True,
            reason=CostGuardReason.DISABLED,
            safe_degraded=False,
        )
    if provider not in policy.approved_providers:
        return AIOperationsDecision(
            allowed=False,
            reason=CostGuardReason.PROVIDER_NOT_APPROVED,
            safe_degraded=True,
        )
    if pricing is None:
        return AIOperationsDecision(
            allowed=False,
            reason=CostGuardReason.PRICING_MISSING,
            safe_degraded=True,
        )
    if observed_at.tzinfo is None or observed_at.utcoffset() != timedelta(0):
        raise ValueError("provider preflight time must be UTC")
    if observed_at < pricing.observed_at or (
        observed_at - pricing.observed_at > timedelta(hours=policy.cost.price_maximum_age_hours)
    ):
        return AIOperationsDecision(
            allowed=False,
            reason=CostGuardReason.PRICING_STALE,
            safe_degraded=True,
        )
    if not 0 <= maximum_input_tokens <= policy.cost.maximum_input_tokens:
        raise ValueError("input token projection exceeds the approved bound")
    if not 0 <= maximum_output_tokens <= policy.cost.maximum_output_tokens:
        raise ValueError("output token projection exceeds the approved bound")
    projected = (
        Decimal(maximum_input_tokens) * pricing.input_token_rate_usd_per_million
        + Decimal(maximum_output_tokens) * pricing.output_token_rate_usd_per_million
    ) / Decimal(1_000_000)
    if projected > policy.cost.cost_per_successful_request_ceiling_usd:
        return AIOperationsDecision(
            allowed=False,
            reason=CostGuardReason.PROJECTED_COST_EXCEEDED,
            projected_cost_usd=projected,
            safe_degraded=True,
        )
    return AIOperationsDecision(
        allowed=True,
        reason=CostGuardReason.ALLOWED,
        projected_cost_usd=projected,
        safe_degraded=False,
    )


def record_ai_request_cost(
    recorder: _AIOperationsRecorder,
    *,
    provider: Literal["bedrock", "fake"],
    decision: AIOperationsDecision,
    actual_cost_usd: Decimal | None = None,
) -> None:
    recorder.record_ai_operation(
        AIOperationsObservation(
            signal=AIOperationsSignal.COST_GUARD_DECISION,
            value=1.0,
            provider=provider,
            outcome="success" if decision.allowed else "denied",
            cost_guard_reason=decision.reason,
        )
    )
    if actual_cost_usd is not None:
        recorder.record_ai_operation(
            AIOperationsObservation(
                signal=AIOperationsSignal.REQUEST_COST,
                value=float(actual_cost_usd),
                provider=provider,
                outcome="success",
            )
        )


def record_rag_result(
    recorder: _AIOperationsRecorder,
    *,
    retrieval_quality: float,
    groundedness_proxy: float,
    citation_coverage: float,
    abstained: bool,
) -> None:
    outcome: Literal["success", "abstained"] = "abstained" if abstained else "success"
    for signal, value in (
        (AIOperationsSignal.RETRIEVAL_QUALITY, retrieval_quality),
        (AIOperationsSignal.GROUNDEDNESS, groundedness_proxy),
        (AIOperationsSignal.CITATION_COVERAGE, citation_coverage),
        (AIOperationsSignal.ABSTENTION, 1.0 if abstained else 0.0),
    ):
        recorder.record_ai_operation(
            AIOperationsObservation(signal=signal, value=value, outcome=outcome)
        )


def record_dependency_result(
    recorder: _AIOperationsRecorder,
    *,
    dependency: DependencyKind,
    available: bool,
    degraded: bool = False,
) -> None:
    recorder.record_ai_operation(
        AIOperationsObservation(
            signal=AIOperationsSignal.DEPENDENCY_AVAILABILITY,
            value=1.0 if available else 0.0,
            dependency=dependency,
            outcome="degraded" if degraded else ("success" if available else "denied"),
        )
    )


def record_admission_state(
    recorder: _AIOperationsRecorder,
    *,
    reason: AdmissionReason,
    allowed: bool,
    queue_depth: int,
) -> None:
    if queue_depth < 0:
        raise ValueError("queue depth cannot be negative")
    recorder.record_ai_operation(
        AIOperationsObservation(
            signal=AIOperationsSignal.ADMISSION_DECISION,
            value=1.0,
            outcome="success" if allowed else "denied",
            admission_reason=reason,
        )
    )
    recorder.record_ai_operation(
        AIOperationsObservation(
            signal=AIOperationsSignal.QUEUE_DEPTH,
            value=float(queue_depth),
            outcome="success" if allowed else "degraded",
        )
    )


def record_evaluation_binding(
    recorder: _AIOperationsRecorder,
    binding: RuntimeIdentityBinding,
) -> None:
    recorder.record_ai_operation(
        AIOperationsObservation(
            signal=AIOperationsSignal.CONFIGURATION_DRIFT,
            value=0.0 if binding.evaluation_status is EvaluationBindingStatus.EXACT_MATCH else 1.0,
            outcome=(
                "success"
                if binding.evaluation_status is EvaluationBindingStatus.EXACT_MATCH
                else "degraded"
            ),
            evaluation_status=binding.evaluation_status,
        )
    )
