"""Local-only composition tests for OpenTelemetry providers and collector config."""

from __future__ import annotations

from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from enterprise_ai_platform import __version__
from enterprise_ai_platform.api.errors import AuthenticationInvalidError
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)
from enterprise_ai_platform.telemetry.models import (
    METRIC_NAMES,
    METRIC_SERIES_UPPER_BOUND,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import (
    BoundedInMemorySpanExporter,
    build_in_memory_telemetry,
)
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe
from tests.fakes.telemetry import (
    EXCEPTION_DETAIL,
    DeterministicClock,
    FailingSpanExporter,
)

ROOT = Path(__file__).resolve().parents[2]
COLLECTOR_CONFIG = ROOT / "configs/observability/otel-collector.local.yaml"


def test_resource_attributes_and_metric_units_are_exact(
    telemetry_factory,
) -> None:  # type: ignore[no-untyped-def]
    composition = telemetry_factory()

    with composition.runtime.start_scope(
        TelemetryStage.API,
        TelemetryOperation.REQUEST,
    ) as scope:
        scope.finish(TelemetryOutcome.SUCCESS)
    composition.runtime.record_tokens(
        stage=TelemetryStage.LLM,
        operation=TelemetryOperation.CHAT,
        input_tokens=2,
        output_tokens=3,
        total_tokens=5,
        prompt_version="w3-001.v1",
    )
    composition.runtime.record_retrieval_results(2)
    composition.runtime.record_agent_steps(
        4,
        outcome=TelemetryOutcome.SUCCESS,
        terminal_reason="answer_reference_ready",
    )
    composition.runtime.record_tool_call(
        tool_name="get_service_status",
        tool_version="1.0",
        outcome=TelemetryOutcome.SUCCESS,
    )
    composition.runtime.force_flush()

    assert isinstance(composition.span_exporter, BoundedInMemorySpanExporter)
    spans = composition.span_exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].resource.attributes == {
        "service.name": "enterprise-ai-api",
        "service.version": __version__,
        "deployment.environment.name": "sandbox",
    }

    metrics_data = composition.metric_reader.get_metrics_data()
    metrics = {
        metric.name: metric
        for resource_metrics in metrics_data.resource_metrics
        for scope_metrics in resource_metrics.scope_metrics
        for metric in scope_metrics.metrics
    }
    assert set(metrics) == set(METRIC_NAMES.values()) - {
        METRIC_NAMES["export_failures"],
        METRIC_NAMES["dropped"],
    }
    assert metrics[METRIC_NAMES["stage_executions"]].unit == "{execution}"
    assert metrics[METRIC_NAMES["stage_duration"]].unit == "s"
    assert metrics[METRIC_NAMES["usage_tokens"]].unit == "{token}"
    assert metrics[METRIC_NAMES["retrieval_results"]].unit == "{item}"
    assert metrics[METRIC_NAMES["agent_steps"]].unit == "{step}"
    assert metrics[METRIC_NAMES["agent_tool_calls"]].unit == "{call}"
    series_count = sum(len(metric.data.data_points) for metric in metrics.values())
    assert 0 < series_count <= METRIC_SERIES_UPPER_BOUND


def test_failing_exporter_preserves_business_flow_and_redacts_exception(
    valid_settings: Settings,
) -> None:
    clock = DeterministicClock()
    failing = FailingSpanExporter()
    composition = build_in_memory_telemetry(
        settings=valid_settings,
        monotonic=clock.monotonic,
        unix_time_ns=clock.unix_time_ns,
        span_exporter=failing,
    )
    values = valid_settings.model_dump(mode="python")
    values.update(api_routes_enabled=True, telemetry_enabled=True)
    settings = Settings(_env_file=None, **values)
    authenticator = FakeAuthenticator(
        AuthContext(
            subject_id="reader-a",
            tenant_id="tenant-a",
            roles=frozenset({Role.READER}),
            clearance=Classification.INTERNAL,
        )
    )
    rag = FakeRAGService([AbstentionResult(reason="insufficient_evidence", usage=None)])
    application = create_app(
        settings,
        authenticator=authenticator,
        rag_service=rag,
        readiness_probe=FakeReadinessProbe(),
        telemetry_runtime=composition.runtime,
    )
    client = TestClient(application)

    accepted = client.post("/v1/query", json={"query": "safe request"})
    authenticator.outcome = AuthenticationInvalidError()
    denied = client.post("/v1/query", json={"query": "must not reach RAG"})

    assert accepted.status_code == 200
    assert accepted.json()["reason"] == "insufficient_evidence"
    assert denied.status_code == 401
    assert denied.json()["error"]["code"] == "authentication_invalid"
    assert len(rag.calls) == 1
    assert failing.export_calls == 4
    captured = "\n".join(record.model_dump_json() for record in composition.log_sink.records())
    assert "telemetry_export_failed" in captured
    assert EXCEPTION_DETAIL not in captured
    composition.runtime.shutdown()


def test_runtime_lifecycle_rejects_double_shutdown(telemetry_factory) -> None:
    composition = telemetry_factory()

    assert composition.runtime.force_flush() is True
    assert composition.runtime.shutdown() is True
    assert composition.runtime.shutdown() is False
    assert composition.runtime.force_flush() is False


def test_bounded_runtime_drops_oldest_and_increments_safe_drop_metric(
    telemetry_factory,
) -> None:  # type: ignore[no-untyped-def]
    composition = telemetry_factory()

    for _ in range(513):
        with composition.runtime.start_scope(
            TelemetryStage.API,
            TelemetryOperation.REQUEST,
        ) as scope:
            scope.finish(TelemetryOutcome.SUCCESS)
    composition.runtime.force_flush()

    assert isinstance(composition.span_exporter, BoundedInMemorySpanExporter)
    assert len(composition.span_exporter.get_finished_spans()) == 512
    assert len(composition.log_sink.records()) == 512
    metrics_data = composition.metric_reader.get_metrics_data()
    dropped_metric = next(
        metric
        for resource_metrics in metrics_data.resource_metrics
        for scope_metrics in resource_metrics.scope_metrics
        for metric in scope_metrics.metrics
        if metric.name == METRIC_NAMES["dropped"]
    )
    assert sum(point.value for point in dropped_metric.data.data_points) >= 1


def test_collector_configuration_is_exact_loopback_debug_only() -> None:
    configuration = yaml.safe_load(COLLECTOR_CONFIG.read_text(encoding="utf-8"))

    assert configuration == {
        "receivers": {
            "otlp": {
                "protocols": {
                    "grpc": {"endpoint": "127.0.0.1:4317"},
                    "http": {"endpoint": "127.0.0.1:4318"},
                }
            }
        },
        "processors": {
            "batch": {
                "timeout": "1s",
                "send_batch_size": 64,
                "send_batch_max_size": 64,
            }
        },
        "exporters": {"debug": {}},
        "service": {
            "pipelines": {
                signal: {
                    "receivers": ["otlp"],
                    "processors": ["batch"],
                    "exporters": ["debug"],
                }
                for signal in ("traces", "metrics", "logs")
            }
        },
    }
    serialized = COLLECTOR_CONFIG.read_text(encoding="utf-8").casefold()
    for forbidden in (
        "0.0.0.0",  # noqa: S104 - intentional forbidden binding sentinel
        "memory_limiter",
        "sending_queue",
        "jaeger",
        "prometheus",
        "cloudwatch",
        "x-ray",
        "${",
        "tls:",
    ):
        assert forbidden not in serialized
