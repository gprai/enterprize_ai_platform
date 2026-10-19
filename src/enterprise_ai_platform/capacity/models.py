"""Strict immutable capacity, scaling, cost, and evidence contracts for W8-004."""

from __future__ import annotations

import math
from datetime import UTC, datetime
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SHA256_PATTERN = r"^[0-9a-f]{64}$"
SAFE_CODE_PATTERN = r"^[A-Z][A-Z0-9_]{0,79}$"


class CapacityModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        str_strip_whitespace=True,
        validate_default=True,
    )


class CapacityClassification(StrEnum):
    PASSED = "PASS"
    FAIL = "FAIL"


class EngineDecision(StrEnum):
    SELECTED = "selected"
    CONDITIONAL_NOT_SELECTED = "conditional_not_selected"
    NOT_ADOPTED = "not_adopted"


class EvidenceScope(StrEnum):
    OFFLINE_SYNTHETIC_ONLY = "offline_synthetic_only"


class DemandAssumptions(CapacityModel):
    sustained_requests_per_second: Literal[1] = 1
    spike_requests_per_second: Literal[3] = 3
    spike_duration_seconds: Literal[30] = 30
    concurrency_levels: tuple[Literal[1, 4, 8], ...] = (1, 4, 8)
    warmup_requests: Literal[20] = 20
    measured_requests_per_level: Literal[200] = 200
    assumed_input_tokens_per_request: Literal[2048] = 2048
    assumed_output_tokens_per_request: Literal[256] = 256
    sustained_input_tokens_per_second: Literal[2048] = 2048
    sustained_output_tokens_per_second: Literal[256] = 256
    spike_input_tokens_per_second: Literal[6144] = 6144
    spike_output_tokens_per_second: Literal[768] = 768
    maximum_input_tokens: Literal[16384] = 16384
    maximum_output_tokens: Literal[512] = 512

    @field_validator("concurrency_levels")
    @classmethod
    def require_exact_concurrency_levels(
        cls, values: tuple[Literal[1, 4, 8], ...]
    ) -> tuple[Literal[1, 4, 8], ...]:
        if values != (1, 4, 8):
            raise ValueError("concurrency levels must be exactly 1, 4, and 8")
        return values


class LatencyTargets(CapacityModel):
    p95_milliseconds_less_than: Literal[4000] = 4000
    p99_milliseconds_less_than: Literal[10000] = 10000
    request_timeout_seconds: Literal[25] = 25
    cold_start_ceiling_seconds: Literal[120] = 120


class ComputeTargets(CapacityModel):
    per_pod_inflight_requests: Literal[4] = 4
    queue_capacity: Literal[0] = 0
    minimum_replicas: Literal[2] = 2
    maximum_replicas: Literal[4] = 4
    cpu_request_millicores: Literal[500] = 500
    cpu_limit_millicores: Literal[1000] = 1000
    memory_request_mebibytes: Literal[1024] = 1024
    memory_limit_mebibytes: Literal[2048] = 2048
    gpu_required: Literal[False] = False
    gpu_count: Literal[0] = 0


class ScalingContract(CapacityModel):
    cpu_target_percent: Literal[70] = 70
    memory_target_percent: Literal[75] = 75
    scale_up_stabilization_seconds: Literal[0] = 0
    scale_up_pods: Literal[1] = 1
    scale_up_percent: Literal[100] = 100
    scale_up_period_seconds: Literal[60] = 60
    scale_up_select_policy: Literal["Max"] = "Max"
    scale_down_stabilization_seconds: Literal[300] = 300
    scale_down_pods: Literal[1] = 1
    scale_down_period_seconds: Literal[60] = 60
    scale_down_select_policy: Literal["Min"] = "Min"
    pod_disruption_max_unavailable: Literal[1] = 1


class FailureContract(CapacityModel):
    circuit_breaker_failure_threshold: Literal[5] = 5
    circuit_breaker_open_seconds: Literal[30] = 30
    circuit_breaker_half_open_probes: Literal[1] = 1
    api_retry_attempts: Literal[0] = 0
    provider_maximum_attempts: Literal[2] = 2


class CostGuardrails(CapacityModel):
    monthly_budget_usd: Literal[60] = 60
    daily_alert_usd: Literal[3] = 3
    maximum_paid_evaluation_usd: Literal[5] = 5
    cost_per_successful_request_ceiling: Decimal = Field(
        default=Decimal("0.01"),
        gt=0,
        le=Decimal("0.01"),
    )
    price_maximum_age_hours: Literal[24] = 24

    @field_validator("cost_per_successful_request_ceiling")
    @classmethod
    def require_owner_approved_ceiling(cls, value: Decimal) -> Decimal:
        if value != Decimal("0.01"):
            raise ValueError("cost per successful request ceiling must be USD 0.01")
        return value


class ServingEngineDecision(CapacityModel):
    engine: Literal[
        "bedrock",
        "sagemaker_realtime",
        "eks_model_serving",
        "karpenter",
        "ray_serve",
        "triton",
    ]
    decision: EngineDecision
    reason_code: str = Field(pattern=SAFE_CODE_PATTERN)


class CapacityPolicy(CapacityModel):
    schema_version: Literal["w8-004.capacity-cost-policy.v1"] = "w8-004.capacity-cost-policy.v1"
    feature_ids: tuple[Literal["CAP-001", "COST-005"], ...] = ("CAP-001", "COST-005")
    region: Literal["ap-southeast-1"] = "ap-southeast-1"
    evidence_scope: EvidenceScope = EvidenceScope.OFFLINE_SYNTHETIC_ONLY
    demand: DemandAssumptions
    latency: LatencyTargets
    compute: ComputeTargets
    scaling: ScalingContract
    failure: FailureContract
    cost: CostGuardrails
    serving_engines: tuple[ServingEngineDecision, ...]
    live_execution: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"
    provisioning: Literal["NOT_RUN"] = "NOT_RUN"

    @model_validator(mode="after")
    def require_engine_decisions(self) -> CapacityPolicy:
        if self.feature_ids != ("CAP-001", "COST-005"):
            raise ValueError("feature ownership must be CAP-001 then COST-005")
        expected = {
            "bedrock": EngineDecision.SELECTED,
            "sagemaker_realtime": EngineDecision.CONDITIONAL_NOT_SELECTED,
            "eks_model_serving": EngineDecision.CONDITIONAL_NOT_SELECTED,
            "karpenter": EngineDecision.CONDITIONAL_NOT_SELECTED,
            "ray_serve": EngineDecision.NOT_ADOPTED,
            "triton": EngineDecision.NOT_ADOPTED,
        }
        actual = {item.engine: item.decision for item in self.serving_engines}
        if len(actual) != len(self.serving_engines) or actual != expected:
            raise ValueError("serving-engine decisions differ from the approved contract")
        return self


class CapacitySample(CapacityModel):
    schema_version: Literal["w8-004.capacity-sample.v1"] = "w8-004.capacity-sample.v1"
    scenario_id: str = Field(pattern=SAFE_CODE_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    observed_at: datetime
    pricing_as_of: datetime
    concurrency: Literal[1, 4, 8]
    duration_seconds: int = Field(gt=0, le=3600)
    successful_requests: int = Field(ge=0, le=100000)
    rejected_requests: int = Field(ge=0, le=100000)
    overload_requests: int = Field(ge=0, le=100000)
    timeout_requests: int = Field(ge=0, le=100000)
    dependency_failure_requests: int = Field(ge=0, le=100000)
    latency_milliseconds: tuple[int, ...] = Field(max_length=100000)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    provider_token_cost_usd: Decimal = Field(ge=Decimal("0"))
    allocated_compute_cost_usd: Decimal = Field(ge=Decimal("0"))
    observability_network_cost_usd: Decimal = Field(ge=Decimal("0"))
    cold_start_seconds: int = Field(ge=0, le=3600)
    scale_out_seconds: int = Field(ge=0, le=3600)
    scale_in_seconds: int = Field(ge=0, le=3600)
    peak_queue_depth: int = Field(ge=0)
    peak_cpu_percent: int = Field(ge=0, le=100)
    peak_memory_percent: int = Field(ge=0, le=100)
    unschedulable_pods: int = Field(ge=0)
    terminated_safely: bool

    @field_validator("observed_at", "pricing_as_of")
    @classmethod
    def require_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("capacity timestamps must be UTC")
        return value.astimezone(UTC)

    @field_validator(
        "provider_token_cost_usd",
        "allocated_compute_cost_usd",
        "observability_network_cost_usd",
    )
    @classmethod
    def require_finite_cost(cls, value: Decimal) -> Decimal:
        if not value.is_finite() or value < 0:
            raise ValueError("cost values must be finite and non-negative")
        return value

    @model_validator(mode="after")
    def require_aggregate_consistency(self) -> CapacitySample:
        if len(self.latency_milliseconds) != self.successful_requests:
            raise ValueError("latency count must equal successful requests")
        if any(value <= 0 for value in self.latency_milliseconds):
            raise ValueError("latencies must be positive")
        return self

    @property
    def attempted_requests(self) -> int:
        return sum(
            (
                self.successful_requests,
                self.rejected_requests,
                self.overload_requests,
                self.timeout_requests,
                self.dependency_failure_requests,
            )
        )


class CapacityEvidence(CapacityModel):
    schema_version: Literal["w8-004.capacity-evidence.v1"] = "w8-004.capacity-evidence.v1"
    scenario_id: str = Field(pattern=SAFE_CODE_PATTERN)
    policy_sha256: str = Field(pattern=SHA256_PATTERN)
    sample_sha256: str = Field(pattern=SHA256_PATTERN)
    classification: CapacityClassification
    reason_codes: tuple[str, ...]
    concurrency: Literal[1, 4, 8]
    attempted_requests: int = Field(gt=0)
    successful_requests: int = Field(gt=0)
    rejected_requests: int = Field(ge=0)
    overload_requests: int = Field(ge=0)
    timeout_requests: int = Field(ge=0)
    dependency_failure_requests: int = Field(ge=0)
    throughput_requests_per_second: Decimal = Field(ge=Decimal("0"))
    input_tokens_per_second: Decimal = Field(ge=Decimal("0"))
    output_tokens_per_second: Decimal = Field(ge=Decimal("0"))
    p50_latency_milliseconds: int = Field(gt=0)
    p95_latency_milliseconds: int = Field(gt=0)
    p99_latency_milliseconds: int = Field(gt=0)
    total_cost_usd: Decimal = Field(ge=Decimal("0"))
    cost_per_successful_request_usd: Decimal = Field(ge=Decimal("0"))
    production_capacity_claimed: Literal[False] = False
    live_execution: Literal["NOT_AUTHORIZED"] = "NOT_AUTHORIZED"

    @field_validator(
        "throughput_requests_per_second",
        "input_tokens_per_second",
        "output_tokens_per_second",
        "total_cost_usd",
        "cost_per_successful_request_usd",
    )
    @classmethod
    def require_finite_metric(cls, value: Decimal) -> Decimal:
        if not value.is_finite() or value < 0 or math.isnan(float(value)):
            raise ValueError("evidence metrics must be finite and non-negative")
        return value

    @field_validator("reason_codes")
    @classmethod
    def require_safe_unique_reasons(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or len(values) != len(set(values)):
            raise ValueError("reason codes must be non-empty and unique")
        for value in values:
            if not value or len(value) > 80 or not value.replace("_", "").isalnum():
                raise ValueError("reason code is unsafe")
        return values
