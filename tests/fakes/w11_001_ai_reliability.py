"""Content-free W11-001 reliability evidence builders."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

from enterprise_ai_platform.telemetry.ai_reliability import (
    AIReliabilityPolicy,
    BurnRateEvidence,
    CollectionStatus,
    EvaluationBatch,
    SLIEvidence,
    ThresholdDirection,
)

OBSERVED_AT = datetime(2026, 10, 19, tzinfo=UTC)


def passing_sli_evidence(policy: AIReliabilityPolicy) -> tuple[SLIEvidence, ...]:
    return tuple(
        SLIEvidence(
            sli_id=contract.sli_id,
            collection_status=CollectionStatus.MEASURED,
            sample_count=contract.minimum_samples,
            observed_value=(
                contract.threshold
                if contract.direction is ThresholdDirection.MINIMUM
                else max(Decimal(0), contract.threshold)
            ),
            observed_at=OBSERVED_AT,
            source_identity_sha256="a" * 64,
            correlated_request_count=contract.minimum_samples,
            correlation_digest_sha256="b" * 64,
        )
        for contract in policy.slis
    )


def passing_batch(policy: AIReliabilityPolicy) -> EvaluationBatch:
    return EvaluationBatch(
        sli_evidence=passing_sli_evidence(policy),
        burn_evidence=(
            BurnRateEvidence(
                tier="fast",
                collection_status=CollectionStatus.MEASURED,
                short_window_burn_factor=Decimal(0),
                long_window_burn_factor=Decimal(0),
                short_window_events=20,
                observed_at=OBSERVED_AT,
            ),
            BurnRateEvidence(
                tier="slow",
                collection_status=CollectionStatus.MEASURED,
                short_window_burn_factor=Decimal(0),
                long_window_burn_factor=Decimal(0),
                short_window_events=20,
                observed_at=OBSERVED_AT,
            ),
        ),
    )
