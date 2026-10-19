"""Unit checks for W10-004 policy and fail-closed decisions."""

from datetime import UTC, datetime, timedelta
from decimal import Decimal

from enterprise_ai_platform.telemetry.ai_operations import (
    CostGuardReason,
    PricingSnapshot,
    load_ai_operations_policy,
    preflight_provider_call,
)


def _pricing(observed_at: datetime) -> PricingSnapshot:
    return PricingSnapshot(
        observed_at=observed_at,
        input_token_rate_usd_per_million=Decimal("0.41"),
        output_token_rate_usd_per_million=Decimal("3.39"),
    )


def test_approved_maximum_request_is_below_cost_ceiling() -> None:
    policy = load_ai_operations_policy()
    observed_at = datetime(2026, 10, 18, tzinfo=UTC)
    decision = preflight_provider_call(
        policy,
        enabled=True,
        provider="bedrock",
        pricing=_pricing(observed_at),
        observed_at=observed_at + timedelta(hours=1),
        maximum_input_tokens=16_384,
        maximum_output_tokens=512,
    )
    assert decision.allowed is True
    assert decision.reason is CostGuardReason.ALLOWED
    assert decision.projected_cost_usd == Decimal("0.00845312")


def test_stale_pricing_and_unapproved_provider_fail_closed() -> None:
    policy = load_ai_operations_policy()
    observed_at = datetime(2026, 10, 18, tzinfo=UTC)
    stale = preflight_provider_call(
        policy,
        enabled=True,
        provider="bedrock",
        pricing=_pricing(observed_at),
        observed_at=observed_at + timedelta(hours=25),
        maximum_input_tokens=1,
        maximum_output_tokens=1,
    )
    denied = preflight_provider_call(
        policy,
        enabled=True,
        provider="fake",
        pricing=_pricing(observed_at),
        observed_at=observed_at,
        maximum_input_tokens=1,
        maximum_output_tokens=1,
    )
    assert stale.reason is CostGuardReason.PRICING_STALE
    assert denied.reason is CostGuardReason.PROVIDER_NOT_APPROVED
    assert stale.safe_degraded and denied.safe_degraded
