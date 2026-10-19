"""Composition checks for W10-004 observations through the existing runtime."""

from decimal import Decimal

from enterprise_ai_platform.telemetry.ai_operations import (
    AIOperationsDecision,
    CostGuardReason,
    DependencyKind,
    record_ai_request_cost,
    record_dependency_result,
)
from tests.fakes.w10_004_ai_operations import RecordingAIOperationsRuntime


def test_ai_operations_use_one_existing_telemetry_runtime() -> None:
    runtime = RecordingAIOperationsRuntime()
    decision = AIOperationsDecision(
        allowed=True,
        reason=CostGuardReason.ALLOWED,
        projected_cost_usd=Decimal("0.00845312"),
        safe_degraded=False,
    )
    record_ai_request_cost(
        runtime,
        provider="bedrock",
        decision=decision,
        actual_cost_usd=Decimal("0.001"),
    )
    record_dependency_result(
        runtime,
        dependency=DependencyKind.MODEL,
        available=True,
    )
    assert [item.signal for item in runtime.observations] == [
        "cost_guard_decision",
        "request_cost",
        "dependency_availability",
    ]
