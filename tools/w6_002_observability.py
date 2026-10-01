"""Validate W6-002 deployment-readiness artifacts without external access."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

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
    grpc = collector["receivers"]["otlp"]["protocols"]["grpc"]
    limiter = collector["processors"]["memory_limiter"]
    batch = collector["processors"]["batch"]
    if grpc != {"endpoint": "127.0.0.1:4317"}:
        raise W6002Error("collector ingress must remain pod-local gRPC")
    if limiter != {"check_interval": "1s", "limit_mib": 128, "spike_limit_mib": 32}:
        raise W6002Error("collector memory limit differs")
    if batch != {"send_batch_size": 64, "timeout": "1s"}:
        raise W6002Error("collector batch differs")
    for exporter in ("awsxray", "awsemf"):
        values = collector["exporters"][exporter]
        if values["region"] != "ap-southeast-1" or values["timeout"] != "1s":
            raise W6002Error(f"{exporter} region or timeout differs")
        if values["sending_queue"] != {
            "enabled": True,
            "queue_size": 512,
            "num_consumers": 1,
        }:
            raise W6002Error(f"{exporter} queue differs")
        if values["retry_on_failure"] != {
            "enabled": True,
            "initial_interval": "1s",
            "max_interval": "5s",
            "max_elapsed_time": "30s",
        }:
            raise W6002Error(f"{exporter} retry differs")

    slo = _load_yaml(root / REQUIRED_PATHS[1])
    if slo["schema_version"] != "w6-002.slo.v1" or slo["owner"] != "Gyan Prakash Rai":
        raise W6002Error("SLO identity differs")
    if slo["window"] != {
        "rolling_days": 30,
        "minimum_eligible_events": 100,
        "below_minimum_status": "NO_DATA",
    }:
        raise W6002Error("SLO evidence window differs")
    if slo["alerting"] != {
        "primary_owner": "Gyan Prakash Rai",
        "backup_owner": None,
        "local_destination": "synthetic-receiver",
        "live_destination": None,
        "live_destination_owner": "W6-004",
    }:
        raise W6002Error("alert ownership or destination differs")

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

    alerts = _load_yaml(root / REQUIRED_PATHS[3])
    names = {
        rule["alert"]
        for group in alerts.get("groups", [])
        for rule in group.get("rules", [])
        if "alert" in rule
    }
    if names != EXPECTED_ALERTS:
        raise W6002Error("alert inventory differs")

    dashboard = json.loads((root / REQUIRED_PATHS[4]).read_text(encoding="utf-8"))
    if dashboard.get("uid") != "enterprise-ai-w6-002" or len(dashboard.get("panels", [])) != 8:
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
