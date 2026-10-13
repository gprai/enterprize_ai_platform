"""Contract tests for W4-003 telemetry allowlists and strict schemas."""

from __future__ import annotations

import math
from uuid import UUID

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.telemetry.models import (
    SPAN_NAMES,
    STRUCTURED_LOG_FIELD_ALLOWLIST,
    TELEMETRY_ATTRIBUTE_ALLOWLIST,
    TELEMETRY_SCHEMA_VERSION,
    RuntimeConfigurationHashes,
    SafeLogRecord,
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
)
from tests.fakes.telemetry import SECURITY_SENTINELS


def _valid_log_values() -> dict[str, object]:
    return {
        "timestamp_unix_nano": 1_800_000_000_000_000_000,
        "event_name": TelemetryEventName.STAGE_COMPLETED,
        "service_name": "enterprise-ai-api",
        "request_id": UUID("00000000-0000-4000-8000-000000000001"),
        "trace_id": "1" * 32,
        "span_id": "2" * 16,
        "stage": TelemetryStage.RAG,
        "operation": TelemetryOperation.ANSWER,
        "outcome": TelemetryOutcome.SUCCESS,
        "duration_ms": 1.0,
        "prompt_version": "w3-001.v1",
    }


def test_schema_version_events_and_fields_are_exact() -> None:
    assert TELEMETRY_SCHEMA_VERSION == "w4-003.telemetry.v1"
    assert {event.value for event in TelemetryEventName} == {
        "stage.completed",
        "security.decision",
        "approval.decision",
        "telemetry.export_failure",
        "telemetry.record_dropped",
        "runtime.configuration",
    }
    assert TELEMETRY_ATTRIBUTE_ALLOWLIST == frozenset(SafeTelemetryAttributes.model_fields)
    assert STRUCTURED_LOG_FIELD_ALLOWLIST == frozenset(SafeLogRecord.model_fields)
    assert {
        "request_id",
        "trace_id",
        "span_id",
        "tenant_id",
        "subject_id",
        "approval_id",
        "run_id",
        "query",
        "source_id",
        "document_id",
        "chunk_id",
    }.isdisjoint(TELEMETRY_ATTRIBUTE_ALLOWLIST)


def test_span_names_cover_each_approved_stage_operation_pair() -> None:
    assert len(SPAN_NAMES) == len(set(SPAN_NAMES.values()))
    assert SPAN_NAMES[(TelemetryStage.API, TelemetryOperation.REQUEST)] == (
        "enterprise_ai.api.request"
    )
    assert SPAN_NAMES[(TelemetryStage.RAG, TelemetryOperation.ANSWER)] == (
        "enterprise_ai.rag.answer"
    )
    assert (
        SPAN_NAMES[(TelemetryStage.APPROVAL, TelemetryOperation.EVALUATE)]
        == "enterprise_ai.approval.evaluate"
    )
    assert (
        SPAN_NAMES[(TelemetryStage.GRAPH, TelemetryOperation.SAFE_TERMINAL)]
        == "enterprise_ai.agent.safe_terminal"
    )


def test_models_are_strict_immutable_and_reject_extra_fields() -> None:
    attributes = SafeTelemetryAttributes(
        stage=TelemetryStage.API,
        operation=TelemetryOperation.REQUEST,
    )
    with pytest.raises(ValidationError):
        SafeTelemetryAttributes.model_validate(
            {"stage": "api", "operation": "request"},
            strict=True,
        )
    with pytest.raises(ValidationError):
        SafeTelemetryAttributes(
            stage=TelemetryStage.API,
            operation=TelemetryOperation.REQUEST,
            query="not-allowed",  # type: ignore[call-arg]
        )
    with pytest.raises(ValidationError):
        attributes.stage = TelemetryStage.RAG  # type: ignore[misc]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("terminal_reason", "arbitrary_reason"),
        ("safe_error_code", "raw_exception_value"),
        ("prompt_version", "unbounded-prompt-version"),
        ("graph_version", "unbounded-graph-version"),
        ("tool_name", "arbitrary-tool"),
        ("tool_version", "999"),
    ],
)
def test_unapproved_bounded_values_are_rejected(field: str, value: str) -> None:
    values: dict[str, object] = {
        "stage": TelemetryStage.API,
        "operation": TelemetryOperation.REQUEST,
        field: value,
    }

    with pytest.raises(ValidationError):
        SafeTelemetryAttributes(**values)


@pytest.mark.parametrize("duration", [-1.0, math.inf, -math.inf, math.nan])
def test_log_schema_rejects_negative_or_non_finite_duration(duration: float) -> None:
    values = _valid_log_values()
    values["duration_ms"] = duration

    with pytest.raises(ValidationError):
        SafeLogRecord(**values)


def test_log_requires_complete_trace_and_token_groups() -> None:
    values = _valid_log_values()
    values.pop("span_id")
    with pytest.raises(ValidationError, match="trace and span"):
        SafeLogRecord(**values)

    values = _valid_log_values()
    values.update(input_tokens=1, output_tokens=2)
    with pytest.raises(ValidationError, match="token counts"):
        SafeLogRecord(**values)

    values.update(total_tokens=99)
    with pytest.raises(ValidationError, match="inconsistent"):
        SafeLogRecord(**values)


@pytest.mark.parametrize("sentinel", SECURITY_SENTINELS)
def test_sensitive_or_content_fields_cannot_enter_schemas(sentinel: str) -> None:
    for prohibited_field in (
        "query",
        "answer",
        "evidence",
        "tool_arguments",
        "credential",
        "exception_text",
        "tenant_id",
        "subject_id",
    ):
        values = _valid_log_values()
        values[prohibited_field] = sentinel
        with pytest.raises(ValidationError):
            SafeLogRecord(**values)


def test_alert_contract_uses_stable_role_and_external_references() -> None:
    from enterprise_ai_platform.telemetry.slo import AlertOwnershipContract, EvidenceStatus

    contract = AlertOwnershipContract(
        owner_reference="role:platform-observability-primary",
        backup_owner_reference="role:platform-observability-backup",
        destination_reference="external:owner-approved-alert-destination",
        delivery_status=EvidenceStatus.NOT_RUN,
    )
    assert contract.delivery_evidence_sha256 is None
    with pytest.raises(ValidationError):
        AlertOwnershipContract(
            owner_reference="Gyan Prakash Rai",
            backup_owner_reference="role:backup",
            destination_reference="synthetic-receiver",
            delivery_status=EvidenceStatus.NOT_RUN,
        )


def test_runtime_configuration_hashes_are_complete_and_not_metric_labels() -> None:
    hashes = RuntimeConfigurationHashes(
        model_config_sha256="a" * 64,
        prompt_config_sha256="b" * 64,
        embedding_config_sha256="c" * 64,
        retrieval_config_sha256="d" * 64,
    )
    record = SafeLogRecord(
        timestamp_unix_nano=1,
        event_name=TelemetryEventName.RUNTIME_CONFIGURATION,
        service_name="enterprise-ai-api",
        stage=TelemetryStage.API,
        operation=TelemetryOperation.VALIDATE,
        outcome=TelemetryOutcome.SUCCESS,
        **hashes.model_dump(mode="python"),
    )

    assert set(hashes.model_dump(mode="json")).isdisjoint(SafeTelemetryAttributes.model_fields)
    assert record.model_config_sha256 == "a" * 64
