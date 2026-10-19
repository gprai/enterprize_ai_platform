"""Security and privacy checks for W10-004 operations telemetry."""

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.telemetry.ai_operations import (
    AIOperationsObservation,
    PricingSnapshot,
    load_ai_operations_policy,
    preflight_provider_call,
)


def test_observation_rejects_raw_or_high_cardinality_fields() -> None:
    with pytest.raises(ValidationError):
        AIOperationsObservation.model_validate(
            {
                "signal": "request_cost",
                "value": 0.1,
                "raw_prompt": "private customer content",
            }
        )


def test_missing_pricing_denies_an_enabled_provider_call() -> None:
    policy = load_ai_operations_policy()
    decision = preflight_provider_call(
        policy,
        enabled=True,
        provider="bedrock",
        pricing=None,
        observed_at=datetime(2026, 10, 18, tzinfo=UTC),
        maximum_input_tokens=1,
        maximum_output_tokens=1,
    )
    assert decision.allowed is False
    assert decision.safe_degraded is True


def test_pricing_schema_accepts_only_non_negative_rates() -> None:
    with pytest.raises(ValidationError):
        PricingSnapshot(
            observed_at=datetime(2026, 10, 18, tzinfo=UTC),
            input_token_rate_usd_per_million=Decimal("-0.01"),
            output_token_rate_usd_per_million=Decimal("3.39"),
        )
