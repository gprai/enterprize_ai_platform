from __future__ import annotations

from enterprise_ai_platform.telemetry.export import (
    EXPORT_BATCH_SIZE,
    EXPORT_DELAY_SECONDS,
    EXPORT_FLUSH_TIMEOUT_SECONDS,
    EXPORT_QUEUE_CAPACITY,
    EXPORT_SHUTDOWN_TIMEOUT_SECONDS,
    EXPORT_TIMEOUT_SECONDS,
)
from enterprise_ai_platform.telemetry.models import (
    OBSERVABILITY_SCHEMA_VERSION,
    ObservabilityEvidence,
    ObservabilityEvidenceStatus,
)
from enterprise_ai_platform.telemetry.slo import (
    SLIObservation,
    SLODefinition,
    SLOStatus,
    evaluate_slo,
)


def test_export_limits_are_exact_and_finite() -> None:
    assert (
        EXPORT_QUEUE_CAPACITY,
        EXPORT_BATCH_SIZE,
        EXPORT_DELAY_SECONDS,
        EXPORT_TIMEOUT_SECONDS,
        EXPORT_FLUSH_TIMEOUT_SECONDS,
        EXPORT_SHUTDOWN_TIMEOUT_SECONDS,
    ) == (512, 64, 1.0, 1.0, 2.0, 2.0)


def test_observability_evidence_preserves_not_run_cloud_truth() -> None:
    evidence = ObservabilityEvidence(
        check_name="local-exporter-outage",
        status=ObservabilityEvidenceStatus.PASS,
        evidence_scope="local-synthetic",
        handover_target="W6-003",
    )
    assert evidence.schema_version == OBSERVABILITY_SCHEMA_VERSION
    assert evidence.cloud_activity == "NOT RUN"
    assert evidence.deployment_activity == "NOT RUN"


def test_missing_slo_population_is_no_data() -> None:
    definition = SLODefinition(
        slo_id="availability",
        objective=0.999,
        window_seconds=30 * 24 * 60 * 60,
        minimum_eligible_events=100,
    )
    result = evaluate_slo(definition, ())
    assert result.status is SLOStatus.NO_DATA
    assert result.achieved_ratio is None


def test_slo_population_passes_and_fails_deterministically() -> None:
    definition = SLODefinition(
        slo_id="quality",
        objective=0.95,
        window_seconds=30 * 24 * 60 * 60,
        minimum_eligible_events=100,
    )
    passing = tuple(
        SLIObservation(eligible=True, good=index < 95, timestamp_unix_seconds=index)
        for index in range(100)
    )
    failing = tuple(
        SLIObservation(eligible=True, good=index < 94, timestamp_unix_seconds=index)
        for index in range(100)
    )
    assert evaluate_slo(definition, passing).status is SLOStatus.PASS
    assert evaluate_slo(definition, failing).status is SLOStatus.FAIL


def test_pre_exercise_and_rollback_metric_contract_is_exact() -> None:
    from enterprise_ai_platform.telemetry.slo import (
        METRIC_DIMENSIONS,
        METRIC_NAMESPACE,
        EvidenceStatus,
        MetricSeriesReadiness,
    )

    readiness = MetricSeriesReadiness(
        pre_exercise_samples=0,
        rollback_window_samples=0,
        status=EvidenceStatus.NO_DATA,
    )
    assert readiness.namespace == METRIC_NAMESPACE == "EnterpriseAI/Sandbox"
    assert readiness.dimensions == METRIC_DIMENSIONS == ("stage", "operation", "outcome")
