"""Deterministic offline evaluator for aggregate synthetic capacity samples."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from math import ceil

from .errors import CapacityValidationError
from .models import (
    CapacityClassification,
    CapacityEvidence,
    CapacityPolicy,
    CapacitySample,
)
from .policy import policy_identity
from .serialization import fingerprint


def _percentile(values: tuple[int, ...], percentile: Decimal) -> int:
    ordered = sorted(values)
    index = max(0, ceil(Decimal(len(ordered)) * percentile) - 1)
    return ordered[index]


def evaluate_capacity(policy: CapacityPolicy, sample: CapacitySample) -> CapacityEvidence:
    expected_policy_sha256 = policy_identity(policy)
    if sample.policy_sha256 != expected_policy_sha256:
        raise CapacityValidationError("sample policy identity does not match")
    if sample.concurrency not in policy.demand.concurrency_levels:
        raise CapacityValidationError("sample concurrency is not approved")
    if sample.attempted_requests != policy.demand.measured_requests_per_level:
        raise CapacityValidationError("sample request count differs from the measured contract")
    if sample.successful_requests == 0:
        raise CapacityValidationError("zero-success evidence cannot support a capacity decision")
    if sample.pricing_as_of > sample.observed_at:
        raise CapacityValidationError("pricing timestamp cannot be in the future")
    maximum_age = timedelta(hours=policy.cost.price_maximum_age_hours)
    if sample.observed_at - sample.pricing_as_of > maximum_age:
        raise CapacityValidationError("pricing evidence is stale")

    p50 = _percentile(sample.latency_milliseconds, Decimal("0.50"))
    p95 = _percentile(sample.latency_milliseconds, Decimal("0.95"))
    p99 = _percentile(sample.latency_milliseconds, Decimal("0.99"))
    duration = Decimal(sample.duration_seconds)
    throughput = Decimal(sample.successful_requests) / duration
    input_throughput = Decimal(sample.input_tokens) / duration
    output_throughput = Decimal(sample.output_tokens) / duration
    total_cost = sum(
        (
            sample.provider_token_cost_usd,
            sample.allocated_compute_cost_usd,
            sample.observability_network_cost_usd,
        ),
        Decimal("0"),
    )
    cost_per_success = total_cost / Decimal(sample.successful_requests)

    reasons: list[str] = []
    if p95 >= policy.latency.p95_milliseconds_less_than:
        reasons.append("P95_LATENCY_EXCEEDED")
    if p99 >= policy.latency.p99_milliseconds_less_than:
        reasons.append("P99_LATENCY_EXCEEDED")
    if throughput < Decimal(policy.demand.sustained_requests_per_second):
        reasons.append("THROUGHPUT_BELOW_ASSUMPTION")
    if input_throughput < Decimal(policy.demand.sustained_input_tokens_per_second):
        reasons.append("INPUT_TOKEN_THROUGHPUT_BELOW_ASSUMPTION")
    if output_throughput < Decimal(policy.demand.sustained_output_tokens_per_second):
        reasons.append("OUTPUT_TOKEN_THROUGHPUT_BELOW_ASSUMPTION")
    if sample.peak_queue_depth > policy.compute.queue_capacity:
        reasons.append("QUEUE_CAPACITY_EXCEEDED")
    if sample.cold_start_seconds > policy.latency.cold_start_ceiling_seconds:
        reasons.append("COLD_START_EXCEEDED")
    if sample.scale_out_seconds > policy.latency.cold_start_ceiling_seconds:
        reasons.append("SCALE_OUT_EXCEEDED")
    if sample.scale_in_seconds < policy.scaling.scale_down_stabilization_seconds:
        reasons.append("SCALE_IN_TOO_FAST")
    if sample.unschedulable_pods > 0:
        reasons.append("CAPACITY_EXHAUSTED")
    if not sample.terminated_safely:
        reasons.append("UNSAFE_TERMINATION")
    if total_cost > Decimal(policy.cost.maximum_paid_evaluation_usd):
        reasons.append("EVALUATION_COST_EXCEEDED")
    if cost_per_success > policy.cost.cost_per_successful_request_ceiling:
        reasons.append("COST_PER_SUCCESSFUL_REQUEST_EXCEEDED")
    if any(
        (
            sample.rejected_requests,
            sample.overload_requests,
            sample.timeout_requests,
            sample.dependency_failure_requests,
        )
    ):
        reasons.append("REQUEST_FAILURES_OBSERVED")

    classification = CapacityClassification.FAIL if reasons else CapacityClassification.PASSED
    if not reasons:
        reasons.append("BOUNDED_SYNTHETIC_TARGETS_MET")
    return CapacityEvidence(
        scenario_id=sample.scenario_id,
        policy_sha256=expected_policy_sha256,
        sample_sha256=fingerprint(sample),
        classification=classification,
        reason_codes=tuple(reasons),
        concurrency=sample.concurrency,
        attempted_requests=sample.attempted_requests,
        successful_requests=sample.successful_requests,
        rejected_requests=sample.rejected_requests,
        overload_requests=sample.overload_requests,
        timeout_requests=sample.timeout_requests,
        dependency_failure_requests=sample.dependency_failure_requests,
        throughput_requests_per_second=throughput,
        input_tokens_per_second=input_throughput,
        output_tokens_per_second=output_throughput,
        p50_latency_milliseconds=p50,
        p95_latency_milliseconds=p95,
        p99_latency_milliseconds=p99,
        total_cost_usd=total_cost,
        cost_per_successful_request_usd=cost_per_success,
    )
