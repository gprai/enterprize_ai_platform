"""Security, privacy, and cardinality checks for W11-001."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.telemetry.ai_reliability import (
    CollectionStatus,
    MaintenanceWindow,
    SLIEvidence,
    load_ai_reliability_policy,
    maintenance_suppresses,
)


def test_raw_content_and_unknown_labels_are_rejected() -> None:
    with pytest.raises(ValidationError):
        SLIEvidence.model_validate(
            {
                "sli_id": "availability",
                "collection_status": "NOT RUN",
                "sample_count": 0,
                "observed_at": "2026-10-19T00:00:00Z",
                "reason": "pending",
                "raw_prompt": "private content",
            }
        )
    policy = load_ai_reliability_policy()
    assert "request_id" in policy.metric_dimensions.prohibited
    assert "tenant_id" in policy.metric_dimensions.prohibited
    assert "request_id" not in policy.metric_dimensions.allowed


def test_measured_evidence_requires_identity_and_content_free_correlation() -> None:
    with pytest.raises(ValidationError):
        SLIEvidence(
            sli_id="availability",
            collection_status=CollectionStatus.MEASURED,
            sample_count=100,
            observed_value=Decimal(1),
            observed_at=datetime(2026, 10, 19, tzinfo=UTC),
            correlated_request_count=100,
        )


def test_duplicate_or_aliased_yaml_is_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "ai_reliability:\n  schema_version: one\n  schema_version: two\n",
        encoding="utf-8",
    )
    alias = tmp_path / "alias.yaml"
    alias.write_text(
        "ai_reliability: &shared\n  schema_version: w11-001.ai-reliability.v1\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate YAML key"):
        load_ai_reliability_policy(duplicate)
    with pytest.raises(ValueError, match="YAML aliases are not permitted"):
        load_ai_reliability_policy(alias)


def test_maintenance_cannot_suppress_authorization_safety_or_pii() -> None:
    policy = load_ai_reliability_policy()
    starts = datetime(2026, 10, 19, tzinfo=UTC)
    window = MaintenanceWindow(
        window_id="owner-approved-one-off",
        starts_at=starts,
        ends_at=starts + timedelta(minutes=30),
        owner_approval_sha256="a" * 64,
        suppressed_sli_ids=("pii_leakage_rate",),
    )
    with pytest.raises(ValueError, match="unsuppressible"):
        maintenance_suppresses(
            policy,
            window,
            sli_id="pii_leakage_rate",
            observed_at=starts,
        )


def test_naive_evidence_time_is_rejected() -> None:
    with pytest.raises(ValidationError, match="UTC-aware"):
        SLIEvidence(
            sli_id="availability",
            collection_status=CollectionStatus.NOT_RUN,
            sample_count=0,
            observed_at=datetime(2026, 10, 19),
            reason="pending",
        )
