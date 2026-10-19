"""Rollback checks for the W10-004 default-off switch."""

from datetime import UTC, datetime

from enterprise_ai_platform.telemetry.ai_operations import (
    CostGuardReason,
    load_ai_operations_policy,
    preflight_provider_call,
)


def test_disabled_operations_preserve_the_existing_provider_path() -> None:
    decision = preflight_provider_call(
        load_ai_operations_policy(),
        enabled=False,
        provider="fake",
        pricing=None,
        observed_at=datetime(2026, 10, 18, tzinfo=UTC),
        maximum_input_tokens=0,
        maximum_output_tokens=0,
    )
    assert decision.allowed is True
    assert decision.reason is CostGuardReason.DISABLED
    assert decision.safe_degraded is False
