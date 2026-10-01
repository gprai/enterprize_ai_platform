from pathlib import Path

import pytest
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


def test_observability_artifacts_contain_no_secret_or_content_fields() -> None:
    forbidden = (
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "api_key:",
        "prompt_content",
        "answer_content",
        "evidence_content",
        "tenant_id",
    )
    combined = "\n".join(path.read_text(encoding="utf-8") for path in ARTIFACTS).casefold()
    assert not any(token in combined for token in forbidden)


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
