"""Validate W6-002 deployment-readiness artifacts without external access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

PASS_STATUS = "W6-002 OBSERVABILITY CONTRACT VALID — NOT DEPLOYED"  # noqa: S105
REQUIRED_PATHS = (
    "configs/observability/otel-collector.aws.yaml",
    "configs/observability/slo.yaml",
    "configs/chaos/fis-plan.yaml",
    "observability/alerts.yml",
    "observability/dashboards/enterprise-ai-overview.json",
)
EXPECTED_ALERTS = {
    "EnterpriseAIAvailabilityFastBurn",
    "EnterpriseAIAvailabilitySlowBurn",
    "EnterpriseAILatencyP95High",
    "EnterpriseAILatencyP99High",
    "EnterpriseAIRetrievalLatencyP99High",
    "EnterpriseAITelemetryExportFailure",
    "EnterpriseAITelemetryQueueDrop",
    "EnterpriseAIReadinessFailure",
    "EnterpriseAIRetryStorm",
    "EnterpriseAISafetyViolation",
}
EXPECTED_W10_004_ALERTS = {
    "EnterpriseAIBackpressure",
    "EnterpriseAICitationCoverageLow",
    "EnterpriseAIConfigurationDrift",
    "EnterpriseAICostGuardDenied",
    "EnterpriseAIGroundednessLow",
    "EnterpriseAIModelDependencyUnavailable",
    "EnterpriseAIPiiFailure",
    "EnterpriseAIRetrievalDependencyUnavailable",
    "EnterpriseAIRetrievalQualityLow",
    "EnterpriseAIAuthorizationFailure",
}
EXPECTED_W11_001_ALERTS = {
    "EnterpriseAIAvailabilityFastBurnW11",
    "EnterpriseAIAvailabilitySlowBurnW11",
    "EnterpriseAIErrorBudgetExhausted",
    "EnterpriseAISLIEvidenceIndeterminate",
    "EnterpriseAISLIBreach",
}
EXPECTED_W11_001_SLIS = (
    "availability",
    "api_latency_p95",
    "api_latency_p99",
    "retrieval_latency_p99",
    "answer_correctness",
    "grounded_answer_rate",
    "citation_coverage",
    "retrieval_relevance",
    "correct_abstention_rate",
    "unauthorized_retrieval_rate",
    "safety_violation_rate",
    "pii_leakage_rate",
    "ingestion_freshness_hours",
    "retrieval_dependency_availability",
    "model_dependency_availability",
    "tokens_per_successful_query",
    "cost_per_successful_query_usd",
)
EXPECTED_LOCAL_REHEARSALS = {
    "opensearch_unavailable",
    "opensearch_timeout",
    "bedrock_timeout",
    "bedrock_throttle",
    "exporter_outage",
    "exporter_saturation",
    "readiness_failure",
    "retry_storm",
}
EXPECTED_LIVE_SCENARIOS = {
    "availability-zone-interruption",
    "bedrock-unavailable",
    "bounded-load",
    "node-interruption",
    "opensearch-unavailable",
    "pod-interruption",
    "telemetry-delivery-failure",
}


class W6002Error(ValueError):
    """A local artifact differs from the closed W6-002 contract."""


def _load_yaml(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise W6002Error(f"{path.name} must contain one mapping")
    return value


def validate(root: Path) -> str:
    """Validate exact bounded values while performing no network or file writes."""

    for relative_path in REQUIRED_PATHS:
        if not (root / relative_path).is_file():
            raise W6002Error(f"missing W6-002 artifact: {relative_path}")

    collector = _load_yaml(root / REQUIRED_PATHS[0])
    if collector["extensions"]["health_check"] != {"endpoint": "0.0.0.0:13133"}:
        raise W6002Error("collector health endpoint must be reachable by kubelet probes")
    grpc = collector["receivers"]["otlp"]["protocols"]["grpc"]
    limiter = collector["processors"]["memory_limiter"]
    batch = collector["processors"]["batch"]
    if grpc != {"endpoint": "127.0.0.1:4317"}:
        raise W6002Error("collector ingress must remain pod-local gRPC")
    if limiter != {"check_interval": "1s", "limit_mib": 128, "spike_limit_mib": 32}:
        raise W6002Error("collector memory limit differs")
    if batch != {"send_batch_size": 64, "timeout": "1s"}:
        raise W6002Error("collector batch differs")
    exporters = collector["exporters"]
    if exporters["awsxray"] != {"region": "ap-southeast-1", "max_retries": 1}:
        raise W6002Error("awsxray configuration differs")
    if exporters["awsemf"] != {
        "region": "ap-southeast-1",
        "namespace": "EnterpriseAI/Sandbox",
        "log_group_name": "/aws/enterprise-ai-platform/sandbox/application",
        "log_retention": 14,
        "max_retries": 1,
    }:
        raise W6002Error("awsemf configuration differs")
    if exporters["awscloudwatchlogs"] != {
        "region": "ap-southeast-1",
        "log_group_name": "/aws/enterprise-ai-platform/sandbox/application",
        "log_stream_name": "enterprise-ai-api",
    }:
        raise W6002Error("awscloudwatchlogs configuration differs")
    if collector["service"]["pipelines"]["logs"]["exporters"] != ["awscloudwatchlogs"]:
        raise W6002Error("logs must use the log-capable CloudWatch exporter")

    slo = _load_yaml(root / REQUIRED_PATHS[1])
    if slo["schema_version"] != "w6-002.slo.v1" or slo["owner"] != "Gyan Prakash Rai":
        raise W6002Error("SLO identity differs")
    if slo.get("hardening_schema_version") != "w7-001.slo-hardening.v1":
        raise W6002Error("SLO hardening schema differs")
    if slo["window"] != {
        "rolling_days": 30,
        "minimum_eligible_events": 100,
        "below_minimum_status": "NO_DATA",
    }:
        raise W6002Error("SLO evidence window differs")
    if slo["metric_contract"] != {
        "namespace": "EnterpriseAI/Sandbox",
        "dimensions": ["stage", "operation", "outcome"],
        "pre_exercise_readiness": {"status": "NO_DATA", "minimum_samples": 1},
        "rollback_window": {"status": "NO_DATA", "minimum_samples": 1},
        "missing_samples_status": "NO_DATA",
    }:
        raise W6002Error("metric readiness contract differs")
    if slo["alerting"] != {
        "schema_version": "w7-001.slo-hardening.v1",
        "owner_reference": "role:platform-observability-primary",
        "backup_owner_reference": "role:platform-observability-backup",
        "destination_reference": "external:owner-approved-alert-destination",
        "delivery_status": "NOT RUN",
        "delivery_evidence_sha256": None,
    }:
        raise W6002Error("alert ownership or destination differs")
    ai_reliability = slo.get("ai_reliability")
    if not isinstance(ai_reliability, dict):
        raise W6002Error("W11-001 AI reliability contract is missing")
    if (
        ai_reliability.get("schema_version") != "w11-001.ai-reliability.v1"
        or ai_reliability.get("prompt_id") != "W11-001"
        or ai_reliability.get("feature_id") != "OBS-001"
        or ai_reliability.get("status_values") != ["PASS", "FAIL", "NOT RUN", "INDETERMINATE"]
    ):
        raise W6002Error("W11-001 AI reliability identity or statuses differ")
    if tuple(item.get("sli_id") for item in ai_reliability.get("slis", [])) != (
        EXPECTED_W11_001_SLIS
    ):
        raise W6002Error("W11-001 AI SLI inventory differs")
    decision = ai_reliability.get("decision", {})
    if (
        decision.get("automatic_rollback_allowed") is not False
        or decision.get("rollback_requires_reviewed_policy_change") is not True
        or {decision.get(f"gap_{number}_status") for number in ("07", "10", "14")}
        != {"OPEN_UNTIL_OWNER_EVIDENCE"}
    ):
        raise W6002Error("W11-001 release, rollback, or open-gap contract differs")
    maintenance = ai_reliability.get("maintenance", {})
    if maintenance.get("standing_exclusions_allowed") is not False or set(
        maintenance.get("never_suppress_sli_ids", [])
    ) != {
        "unauthorized_retrieval_rate",
        "safety_violation_rate",
        "pii_leakage_rate",
    }:
        raise W6002Error("W11-001 maintenance safety boundary differs")

    fis = _load_yaml(root / REQUIRED_PATHS[2])
    if fis["schema_version"] != "w6-002.fis-plan.v1":
        raise W6002Error("FIS schema differs")
    if fis["classification"] != "plan-only-not-authorized-for-execution":
        raise W6002Error("FIS classification differs")
    if fis["action"] != {
        "id": "aws:eks:pod-delete",
        "maximum_targets": 1,
        "duration_seconds": 300,
    }:
        raise W6002Error("FIS action boundary differs")
    if len(fis["stop_alarms"]) != 2:
        raise W6002Error("FIS requires exactly two stop alarms")
    if fis["local_rehearsals"]["execution"] != "fake-provider-only":
        raise W6002Error("local rehearsal mode differs")
    if set(fis["local_rehearsals"]["scenarios"]) != EXPECTED_LOCAL_REHEARSALS:
        raise W6002Error("local rehearsal inventory differs")
    live_scenarios = fis["live_scenarios"]
    if (
        live_scenarios["execution"] != "unauthorized"
        or live_scenarios["default_status"] != "NOT RUN"
    ):
        raise W6002Error("live resilience execution must remain unauthorized and NOT RUN")
    if {item["id"] for item in live_scenarios["scenarios"]} != EXPECTED_LIVE_SCENARIOS:
        raise W6002Error("live resilience scenario inventory differs")
    if any(item["status"] != "NOT RUN" for item in live_scenarios["scenarios"]):
        raise W6002Error("live resilience scenarios must remain NOT RUN")

    alerts = _load_yaml(root / REQUIRED_PATHS[3])
    names = {
        rule["alert"]
        for group in alerts.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    }
    if names != EXPECTED_ALERTS | EXPECTED_W10_004_ALERTS | EXPECTED_W11_001_ALERTS:
        raise W6002Error("alert inventory differs")
    alert_rules = [
        rule
        for group in alerts.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    ]
    expected_labels = {
        "ownership_ref": "role:platform-observability-primary",
        "destination_ref": "external:owner-approved-alert-destination",
    }
    if any(
        any(rule["labels"].get(key) != value for key, value in expected_labels.items())
        for rule in alert_rules
    ):
        raise W6002Error("alert rule ownership binding differs")

    dashboard = json.loads((root / REQUIRED_PATHS[4]).read_text(encoding="utf-8"))
    if dashboard.get("uid") != "enterprise-ai-w6-002" or len(dashboard.get("panels", [])) != 24:
        raise W6002Error("dashboard identity or panel inventory differs")
    return PASS_STATUS


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("validate",))
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(validate(args.root.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
