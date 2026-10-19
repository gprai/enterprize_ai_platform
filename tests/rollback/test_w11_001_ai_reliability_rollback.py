"""Rollback-review and bounded maintenance checks for W11-001."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import yaml

from enterprise_ai_platform.telemetry.ai_reliability import (
    MaintenanceWindow,
    load_ai_reliability_policy,
    maintenance_suppresses,
)

ROOT = Path(__file__).resolve().parents[2]


def test_existing_w6_thresholds_remain_available_for_reviewed_restore() -> None:
    raw = yaml.safe_load((ROOT / "configs/observability/slo.yaml").read_text(encoding="utf-8"))
    assert raw["objectives"] == {
        "availability_ratio": 0.999,
        "latency_p95_seconds": 4,
        "latency_p99_seconds": 10,
        "retrieval_p99_seconds": 0.75,
        "grounded_or_correct_abstention_ratio": 0.95,
        "recall_at_5": 0.85,
        "isolation_ratio": 1.0,
        "safety_ratio": 1.0,
    }
    policy = load_ai_reliability_policy(ROOT / "configs/observability/slo.yaml")
    assert policy.decision.automatic_rollback_allowed is False
    assert policy.decision.rollback_requires_reviewed_policy_change is True


def test_one_off_maintenance_is_time_bounded_and_operational_only() -> None:
    policy = load_ai_reliability_policy()
    starts = datetime(2026, 10, 19, tzinfo=UTC)
    window = MaintenanceWindow(
        window_id="owner-approved-api-maintenance",
        starts_at=starts,
        ends_at=starts + timedelta(minutes=30),
        owner_approval_sha256="a" * 64,
        suppressed_sli_ids=("availability", "api_latency_p95"),
    )
    assert maintenance_suppresses(
        policy,
        window,
        sli_id="availability",
        observed_at=starts + timedelta(minutes=1),
    )
    assert not maintenance_suppresses(
        policy,
        window,
        sli_id="availability",
        observed_at=window.ends_at,
    )
