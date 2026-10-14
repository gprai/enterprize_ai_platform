"""Exact policy and schema contracts for W9-002 experiment lineage."""

from enterprise_ai_platform.experiment_tracking import (
    ExperimentRun,
    load_experiment_policy,
)
from tests.fakes.w9_002_experiment_tracking import make_input


def test_policy_preserves_exact_local_limits_and_separate_approvals() -> None:
    policy = load_experiment_policy()

    assert policy.feature_ids == ("MLFLOW-001", "RET-003")
    assert policy.region == "ap-southeast-1"
    assert policy.operating_mode == "process_local_memory"
    assert policy.limits.global_active_runs == 1
    assert policy.limits.per_tenant_active_runs == 1
    assert policy.limits.maximum_retained_runs == 100
    assert policy.limits.maximum_parameters == 128
    assert policy.limits.maximum_metrics == 32
    assert policy.limits.maximum_artifacts == 16
    assert policy.limits.maximum_comparison_runs == 16
    assert policy.limits.maximum_run_seconds == 900
    assert policy.limits.automatic_retry_attempts == 0
    assert policy.retention.redacted_export_days == 180
    assert policy.backend.network_access is False
    assert policy.backend.managed_backend == "NOT_AUTHORIZED"
    assert policy.approvals.deployment_approval == "NOT_AUTHORIZED"
    assert policy.approvals.promotion_approval == "NOT_AUTHORIZED"


def test_run_schema_contains_identities_but_no_raw_content_fields() -> None:
    schema = ExperimentRun.model_json_schema()
    rendered = str(schema).casefold()

    for identity in ("dataset", "code", "prompt", "model", "embedding", "retrieval", "evaluation"):
        assert identity in rendered
    for forbidden in (
        "answer_text",
        "question_text",
        "prompt_text",
        "response_text",
        "evidence_text",
    ):
        assert forbidden not in rendered


def test_unknown_cost_is_absent_instead_of_fabricated_as_zero() -> None:
    metric_names = {metric.name for metric in make_input().metrics}

    assert "estimated_cost_usd" not in metric_names
