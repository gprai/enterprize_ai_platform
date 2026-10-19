"""Machine-readable W11-001 schema, metric, alert, and dashboard contracts."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from enterprise_ai_platform.telemetry.ai_reliability import (
    AI_RELIABILITY_METRIC_NAMES,
    AI_RELIABILITY_SCHEMA_VERSION,
    AI_RELIABILITY_SLI_ORDER,
    load_ai_reliability_policy,
)

ROOT = Path(__file__).resolve().parents[2]


def test_all_required_ai_slis_are_measurable_and_versioned() -> None:
    policy = load_ai_reliability_policy(ROOT / "configs/observability/slo.yaml")
    assert policy.schema_version == AI_RELIABILITY_SCHEMA_VERSION
    assert tuple(item.sli_id for item in policy.slis) == AI_RELIABILITY_SLI_ORDER
    assert len(policy.slis) == 17
    for contract in policy.slis:
        assert contract.population
        assert contract.denominator
        assert contract.window == "30d"
        assert contract.minimum_samples > 0
        assert contract.data_source
        assert contract.missing_data_status == "INDETERMINATE"


def test_w6_contract_stays_unchanged_and_w11_is_additive() -> None:
    payload = yaml.safe_load((ROOT / "configs/observability/slo.yaml").read_text(encoding="utf-8"))
    assert payload["schema_version"] == "w6-002.slo.v1"
    assert payload["hardening_schema_version"] == "w7-001.slo-hardening.v1"
    assert payload["ai_reliability"]["schema_version"] == AI_RELIABILITY_SCHEMA_VERSION
    assert payload["ai_reliability"]["feature_id"] == "OBS-001"


def test_metric_names_use_one_existing_namespace_and_stable_labels() -> None:
    assert set(AI_RELIABILITY_METRIC_NAMES) == {
        "decision",
        "error_budget_remaining_ratio",
        "observed_value",
    }
    assert all(
        value.startswith("enterprise_ai.ai.reliability.")
        for value in AI_RELIABILITY_METRIC_NAMES.values()
    )
    policy = load_ai_reliability_policy(ROOT / "configs/observability/slo.yaml")
    assert policy.metric_dimensions.allowed == (
        "stage",
        "operation",
        "outcome",
        "dependency",
        "sli_id",
    )
    assert policy.metric_dimensions.correlation_field == "request_id"
    assert policy.metric_dimensions.correlation_is_metric_dimension is False


def test_alerts_use_paired_burn_windows_and_owned_destinations() -> None:
    alerts = yaml.safe_load((ROOT / "observability/alerts.yml").read_text(encoding="utf-8"))
    rules = [rule for group in alerts["groups"] for rule in group["rules"]]
    names = {rule["alert"] for rule in rules if "alert" in rule}
    assert {
        "EnterpriseAIAvailabilityFastBurnW11",
        "EnterpriseAIAvailabilitySlowBurnW11",
        "EnterpriseAIErrorBudgetExhausted",
        "EnterpriseAISLIEvidenceIndeterminate",
        "EnterpriseAISLIBreach",
    }.issubset(names)
    fast = next(
        rule for rule in rules if rule.get("alert") == "EnterpriseAIAvailabilityFastBurnW11"
    )
    slow = next(
        rule for rule in rules if rule.get("alert") == "EnterpriseAIAvailabilitySlowBurnW11"
    )
    assert "rate5m" in fast["expr"] and "rate1h" in fast["expr"]
    assert "rate30m" in slow["expr"] and "rate6h" in slow["expr"]
    for rule in rules:
        if "alert" in rule:
            assert rule["labels"]["ownership_ref"] == "role:platform-observability-primary"
            assert rule["labels"]["destination_ref"] == (
                "external:owner-approved-alert-destination"
            )


def test_dashboard_covers_decision_budget_and_ai_specific_objectives() -> None:
    dashboard = json.loads(
        (ROOT / "observability/dashboards/enterprise-ai-overview.json").read_text(encoding="utf-8")
    )
    titles = {panel["title"] for panel in dashboard["panels"]}
    assert len(dashboard["panels"]) == 24
    assert {
        "Governed release decision",
        "AI error budget remaining",
        "Correct abstention rate",
        "Unauthorized retrieval rate",
        "PII leakage rate",
        "Ingestion freshness hours",
        "Tokens per successful query",
        "Cost per successful query USD",
    }.issubset(titles)
