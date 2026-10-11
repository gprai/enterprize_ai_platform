import json
from collections.abc import Mapping
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from enterprise_ai_platform.telemetry import ObservabilityEvidence, SafeLogRecord

ROOT = Path(__file__).resolve().parents[2]
ARTIFACTS = (
    ROOT / "configs/observability/otel-collector.aws.yaml",
    ROOT / "configs/observability/slo.yaml",
    ROOT / "configs/chaos/fis-plan.yaml",
    ROOT / "observability/alerts.yml",
    ROOT / "observability/dashboards/enterprise-ai-overview.json",
)


def _field_names(value: object) -> set[str]:
    if isinstance(value, Mapping):
        return {str(key).casefold() for key in value} | {
            name for child in value.values() for name in _field_names(child)
        }
    if isinstance(value, list):
        return {name for child in value for name in _field_names(child)}
    return set()


def test_observability_artifacts_contain_no_secret_or_content_fields() -> None:
    forbidden_text = (
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "api_key:",
    )
    forbidden_fields = {
        "prompt_content",
        "answer_content",
        "evidence_content",
        "tenant_id",
    }
    for path in ARTIFACTS:
        raw = path.read_text(encoding="utf-8")
        assert not any(token in raw.casefold() for token in forbidden_text)
        value = json.loads(raw) if path.suffix == ".json" else yaml.safe_load(raw)
        assert not forbidden_fields.intersection(_field_names(value))

    slo = yaml.safe_load((ROOT / "configs/observability/slo.yaml").read_text(encoding="utf-8"))
    assert slo["correlation_contract"]["raw_prompt_content_allowed"] is False


def test_safe_log_schema_rejects_unapproved_content_field() -> None:
    with pytest.raises(ValidationError):
        SafeLogRecord.model_validate(
            {
                "timestamp_unix_nano": 1,
                "event_name": "stage.completed",
                "service_name": "enterprise-ai-api",
                "stage": "api",
                "operation": "request",
                "outcome": "success",
                "prompt_content": "must-not-be-observable",
            }
        )


def test_observability_evidence_rejects_narrative_content() -> None:
    with pytest.raises(ValidationError):
        ObservabilityEvidence.model_validate(
            {
                "check_name": "local-safe-test",
                "status": "PASS",
                "evidence_scope": "local-synthetic",
                "handover_target": "W6-003",
                "prompt_content": "forbidden",
            }
        )


def test_alert_rules_expose_only_stable_references() -> None:
    alerts = (ROOT / "observability/alerts.yml").read_text(encoding="utf-8")
    assert "owner: gyan-prakash-rai" not in alerts
    assert "ownership_ref: role:platform-observability-primary" in alerts
    assert "destination_ref: external:owner-approved-alert-destination" in alerts
