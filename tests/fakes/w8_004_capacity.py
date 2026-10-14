"""Deterministic aggregate-only fixtures for W8-004 capacity tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from enterprise_ai_platform.capacity import CapacityPolicy, CapacitySample, policy_identity


def valid_sample(policy: CapacityPolicy, **overrides: object) -> CapacitySample:
    observed_at = datetime(2026, 10, 13, 0, 0, tzinfo=UTC)
    values: dict[str, object] = {
        "scenario_id": "BOUNDED_SYNTHETIC_BASELINE",
        "policy_sha256": policy_identity(policy),
        "observed_at": observed_at,
        "pricing_as_of": observed_at - timedelta(hours=1),
        "concurrency": 4,
        "duration_seconds": 100,
        "successful_requests": 200,
        "rejected_requests": 0,
        "overload_requests": 0,
        "timeout_requests": 0,
        "dependency_failure_requests": 0,
        "latency_milliseconds": (1000,) * 200,
        "input_tokens": 204800,
        "output_tokens": 25600,
        "provider_token_cost_usd": Decimal("0.80"),
        "allocated_compute_cost_usd": Decimal("0.30"),
        "observability_network_cost_usd": Decimal("0.10"),
        "cold_start_seconds": 60,
        "scale_out_seconds": 45,
        "scale_in_seconds": 300,
        "peak_queue_depth": 0,
        "peak_cpu_percent": 70,
        "peak_memory_percent": 75,
        "unschedulable_pods": 0,
        "terminated_safely": True,
    }
    values.update(overrides)
    return CapacitySample.model_validate(values, strict=True)
