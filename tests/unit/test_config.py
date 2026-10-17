"""Unit tests for typed, fail-fast settings."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.config import (
    AGENT_STORE_PATH,
    LINUX_AGENT_STORE_PATH,
    WINDOWS_AGENT_STORE_PATH,
    Settings,
)
from enterprise_ai_platform.retrieval.hybrid import RetrievalMode

REQUIRED_ENVIRONMENT_KEYS = (
    "ENTERPRISE_AI_EMBEDDING_MODEL_ID",
    "ENTERPRISE_AI_QDRANT_URL",
    "ENTERPRISE_AI_OPENSEARCH_URL",
)


def test_owner_values_and_test_endpoint_are_valid(
    valid_settings_values: dict[str, object],
) -> None:
    settings = Settings(_env_file=None, **valid_settings_values)

    assert settings.aws_region == "ap-southeast-1"
    assert settings.llm_provider == "fake"
    assert settings.llm_model_id is None
    assert settings.embedding_model_id == "sentence-transformers/all-MiniLM-L6-v2"
    assert settings.qdrant_url.host == "127.0.0.1"
    assert settings.opensearch_url.host == "opensearch.invalid"
    assert settings.request_timeout_seconds == 25
    assert settings.api_routes_enabled is False
    assert settings.api_max_request_body_bytes == 131_072
    assert settings.api_max_query_characters == 10_000
    assert settings.api_readiness_timeout_seconds == 1.0
    assert settings.api_max_inflight_queries == 4
    assert settings.api_query_queue_capacity == 0
    assert settings.api_rate_limit_requests == 60
    assert settings.api_rate_limit_window_seconds == 60
    assert settings.api_rate_limit_maximum_tenants == 1024
    assert settings.api_circuit_breaker_failure_threshold == 5
    assert settings.api_circuit_breaker_open_seconds == 30
    assert settings.api_circuit_breaker_half_open_probes == 1
    assert settings.api_retry_attempts == 0
    assert settings.api_response_streaming_enabled is False
    assert settings.api_drain_timeout_seconds == 20
    assert settings.api_cancellation_timeout_seconds == 2
    assert settings.api_dependency_close_timeout_seconds == 2
    assert settings.api_disconnect_poll_seconds == 0.05
    assert settings.telemetry_enabled is False
    assert settings.telemetry_service_name == "enterprise-ai-api"
    assert settings.telemetry_exporter == "none"
    assert settings.telemetry_otlp_endpoint is None
    assert settings.telemetry_span_capacity == 512
    assert settings.telemetry_log_capacity == 512
    assert settings.telemetry_queue_capacity == 0
    assert settings.telemetry_batch_size == 0
    assert settings.telemetry_export_delay_seconds == 0.0
    assert settings.telemetry_export_timeout_seconds == 0.0
    assert settings.telemetry_retry_count == 0
    assert settings.telemetry_background_workers == 0
    assert settings.telemetry_flush_timeout_seconds == 1.0
    assert settings.telemetry_shutdown_timeout_seconds == 1.0
    assert settings.agent_enabled is False
    assert settings.agent_mock_write_enabled is False
    assert settings.agent_state_schema_version == "w4-002.agent-state.v1"
    assert settings.agent_graph_version == "w4-002.graph.v1"
    assert settings.agent_store_schema_version == "w4-002.agent-store.v1"
    assert str(settings.agent_store_path) == str(AGENT_STORE_PATH)
    assert WINDOWS_AGENT_STORE_PATH == (
        r"E:\AI\.runtime\enterprise_ai_platform\w4-002\agent-control-v1.sqlite3"
    )
    assert LINUX_AGENT_STORE_PATH == (
        "/var/lib/enterprise-ai-platform/w4-002/agent-control-v1.sqlite3"
    )
    assert settings.agent_store_path.is_absolute()
    assert settings.agent_approval_ttl_seconds == 600
    assert settings.agent_terminal_retention_seconds == 86_400
    assert settings.agent_maximum_graph_steps == 8
    assert settings.agent_maximum_tool_calls == 1
    assert settings.agent_maximum_provider_attempts == 1
    assert settings.agent_maximum_total_tokens == 4096
    assert settings.agent_graph_retries == 0
    assert settings.agent_deadline_seconds == 25
    assert settings.agent_maximum_serialized_state_bytes == 16_384
    assert settings.agent_maximum_concurrent_runs == 1
    assert settings.agent_queue_capacity == 0
    assert settings.rag_retrieval_mode is RetrievalMode.VECTOR
    assert settings.rag_reranker_enabled is False


def test_retrieval_mode_accepts_only_explicit_vector_or_hybrid_values(
    valid_settings_values: dict[str, object],
) -> None:
    hybrid = Settings(
        _env_file=None,
        rag_retrieval_mode="hybrid",  # type: ignore[arg-type]
        **valid_settings_values,
    )
    assert hybrid.rag_retrieval_mode is RetrievalMode.HYBRID

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            rag_retrieval_mode="automatic",  # type: ignore[arg-type]
            **valid_settings_values,
        )


def test_reranker_requires_explicit_boolean_activation(
    valid_settings_values: dict[str, object],
) -> None:
    enabled = Settings(
        _env_file=None,
        rag_reranker_enabled="true",  # type: ignore[arg-type]
        **valid_settings_values,
    )
    assert enabled.rag_reranker_enabled is True

    with pytest.raises(ValidationError):
        Settings(
            _env_file=None,
            rag_reranker_enabled="automatic",  # type: ignore[arg-type]
            **valid_settings_values,
        )


def test_w6_002_export_profile_is_exact(
    export_settings: Settings,
) -> None:
    assert export_settings.telemetry_enabled is True
    assert export_settings.telemetry_exporter == "otlp_grpc"
    assert export_settings.telemetry_otlp_endpoint == "http://127.0.0.1:4317"
    assert export_settings.telemetry_queue_capacity == 512
    assert export_settings.telemetry_batch_size == 64
    assert export_settings.telemetry_export_delay_seconds == 1.0
    assert export_settings.telemetry_export_timeout_seconds == 1.0
    assert export_settings.telemetry_retry_count == 0
    assert export_settings.telemetry_background_workers == 1
    assert export_settings.telemetry_flush_timeout_seconds == 2.0
    assert export_settings.telemetry_shutdown_timeout_seconds == 2.0


def test_w6_002_export_profile_accepts_exact_kubernetes_environment_strings(
    valid_settings_values: dict[str, object],
) -> None:
    settings = Settings(
        _env_file=None,
        api_routes_enabled=True,
        telemetry_enabled=True,
        telemetry_exporter="otlp_grpc",
        telemetry_otlp_endpoint="http://127.0.0.1:4317",
        telemetry_queue_capacity="512",  # type: ignore[arg-type]
        telemetry_batch_size="64",  # type: ignore[arg-type]
        telemetry_export_delay_seconds="1.0",  # type: ignore[arg-type]
        telemetry_export_timeout_seconds="1.0",  # type: ignore[arg-type]
        telemetry_background_workers="1",  # type: ignore[arg-type]
        telemetry_flush_timeout_seconds="2.0",  # type: ignore[arg-type]
        telemetry_shutdown_timeout_seconds="2.0",  # type: ignore[arg-type]
        **valid_settings_values,
    )

    assert settings.telemetry_queue_capacity == 512
    assert settings.telemetry_batch_size == 64
    assert settings.telemetry_background_workers == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("telemetry_queue_capacity", "0512"),
        ("telemetry_batch_size", " 64"),
        ("telemetry_background_workers", "true"),
    ],
)
def test_telemetry_integer_literals_reject_noncanonical_environment_strings(
    field: str,
    value: str,
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values.update(
        api_routes_enabled=True,
        telemetry_enabled=True,
        telemetry_exporter="otlp_grpc",
        telemetry_otlp_endpoint="http://127.0.0.1:4317",
        telemetry_queue_capacity="512",
        telemetry_batch_size="64",
        telemetry_export_delay_seconds="1.0",
        telemetry_export_timeout_seconds="1.0",
        telemetry_background_workers="1",
        telemetry_flush_timeout_seconds="2.0",
        telemetry_shutdown_timeout_seconds="2.0",
    )
    values[field] = value

    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_w6_002_export_profile_rejects_non_loopback_endpoint(
    valid_settings_values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="exact approved loopback"):
        Settings(
            _env_file=None,
            api_routes_enabled=True,
            telemetry_enabled=True,
            telemetry_exporter="otlp_grpc",
            telemetry_otlp_endpoint="https://collector.example.com:4317",
            telemetry_queue_capacity=512,
            telemetry_batch_size=64,
            telemetry_export_delay_seconds=1.0,
            telemetry_export_timeout_seconds=1.0,
            telemetry_background_workers=1,
            telemetry_flush_timeout_seconds=2.0,
            telemetry_shutdown_timeout_seconds=2.0,
            **valid_settings_values,
        )


def test_missing_required_values_fail_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in REQUIRED_ENVIRONMENT_KEYS:
        monkeypatch.delenv(key, raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_unresolved_opensearch_placeholder_fails(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values["opensearch_url"] = "TODO_USER"

    with pytest.raises(ValidationError, match="TODO_USER"):
        Settings(_env_file=None, **values)


def test_blank_optional_qdrant_key_becomes_none(
    valid_settings_values: dict[str, object],
) -> None:
    settings = Settings(_env_file=None, **valid_settings_values)
    assert settings.qdrant_api_key is None


def test_sandbox_auth_signing_key_can_be_loaded_from_the_approved_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    valid_settings_values: dict[str, object],
) -> None:
    from enterprise_ai_platform import config

    secret_path = tmp_path / "sandbox-auth-signing-key"
    secret_path.write_text("s" * 32, encoding="utf-8")
    monkeypatch.setattr(config, "SANDBOX_AUTH_SIGNING_KEY_FILE_PATH", secret_path)
    values = dict(valid_settings_values)
    values.update(
        sandbox_auth_enabled=True,
        sandbox_auth_issuer="enterprise-ai-sandbox",
        sandbox_auth_audience="enterprise-ai-api",
        sandbox_auth_tenant_id="synthetic-sandbox-tenant",
        sandbox_auth_signing_key_file=secret_path,
    )

    settings = Settings(_env_file=None, **values)

    assert settings.sandbox_auth_signing_key is not None
    assert settings.sandbox_auth_signing_key.get_secret_value() == "s" * 32


def test_sandbox_auth_signing_key_rejects_two_delivery_sources(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    valid_settings_values: dict[str, object],
) -> None:
    from enterprise_ai_platform import config

    secret_path = tmp_path / "sandbox-auth-signing-key"
    secret_path.write_text("s" * 32, encoding="utf-8")
    monkeypatch.setattr(config, "SANDBOX_AUTH_SIGNING_KEY_FILE_PATH", secret_path)
    values = dict(valid_settings_values)
    values.update(
        sandbox_auth_signing_key="d" * 32,
        sandbox_auth_signing_key_file=secret_path,
    )

    with pytest.raises(ValidationError, match="exactly one delivery source"):
        Settings(_env_file=None, **values)


def test_fake_mode_accepts_blank_model_and_region(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values.update(llm_provider="fake", llm_model_id="", aws_region="")

    settings = Settings(_env_file=None, **values)

    assert settings.llm_provider == "fake"
    assert settings.llm_model_id is None
    assert settings.aws_region is None


@pytest.mark.parametrize(
    ("model_id", "region"),
    [(None, "ap-southeast-1"), ("synthetic.model-v1", None)],
)
def test_bedrock_requires_explicit_model_and_region(
    model_id: str | None,
    region: str | None,
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values.update(
        llm_provider="bedrock",
        llm_model_id=model_id,
        aws_region=region,
    )

    with pytest.raises(ValidationError, match="Bedrock requires"):
        Settings(_env_file=None, **values)


@pytest.mark.parametrize("field", ["llm_model_id", "aws_region"])
def test_llm_placeholders_are_rejected(
    field: str,
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values[field] = "TODO_USER"

    with pytest.raises(ValidationError, match="TODO_USER"):
        Settings(_env_file=None, **values)


def test_unprefixed_llm_environment_variables_are_ignored(
    monkeypatch: pytest.MonkeyPatch,
    valid_settings_values: dict[str, object],
) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "bedrock")
    monkeypatch.setenv("LLM_MODEL_ID", "unapproved.model")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    values = dict(valid_settings_values)
    values.update(llm_model_id=None, aws_region=None)

    settings = Settings(_env_file=None, **values)

    assert settings.llm_provider == "fake"
    assert settings.llm_model_id is None
    assert settings.aws_region is None


def test_external_plain_http_endpoint_is_rejected(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values["qdrant_url"] = "http://qdrant.example.com:6333"

    with pytest.raises(ValidationError, match="HTTPS outside loopback"):
        Settings(_env_file=None, **values)


@pytest.mark.parametrize("timeout", [0, 26])
def test_timeout_must_remain_bounded(
    timeout: int,
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values["request_timeout_seconds"] = timeout

    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("api_max_request_body_bytes", 0),
        ("api_max_request_body_bytes", 131_073),
        ("api_readiness_timeout_seconds", 0.0),
        ("api_readiness_timeout_seconds", 1.01),
        ("api_max_inflight_queries", 0),
        ("api_max_inflight_queries", 5),
        ("api_query_queue_capacity", 1),
        ("api_max_query_characters", 10_001),
        ("api_rate_limit_requests", 61),
        ("api_rate_limit_window_seconds", 61),
        ("api_rate_limit_maximum_tenants", 1025),
        ("api_circuit_breaker_failure_threshold", 6),
        ("api_circuit_breaker_open_seconds", 31),
        ("api_circuit_breaker_half_open_probes", 2),
        ("api_retry_attempts", 1),
        ("api_response_streaming_enabled", True),
        ("api_drain_timeout_seconds", 21),
        ("api_cancellation_timeout_seconds", 3),
        ("api_dependency_close_timeout_seconds", 3),
        ("api_disconnect_poll_seconds", 0.1),
        ("telemetry_span_capacity", 511),
        ("telemetry_log_capacity", 513),
        ("telemetry_queue_capacity", 1),
        ("telemetry_retry_count", 1),
        ("telemetry_background_workers", 1),
        ("telemetry_flush_timeout_seconds", 1.01),
        ("telemetry_shutdown_timeout_seconds", 0.99),
        ("agent_approval_ttl_seconds", 601),
        ("agent_terminal_retention_seconds", 86_401),
        ("agent_maximum_graph_steps", 9),
        ("agent_maximum_tool_calls", 2),
        ("agent_maximum_provider_attempts", 2),
        ("agent_maximum_total_tokens", 4097),
        ("agent_graph_retries", 1),
        ("agent_deadline_seconds", 26),
        ("agent_maximum_serialized_state_bytes", 16_385),
        ("agent_maximum_concurrent_runs", 2),
        ("agent_queue_capacity", 1),
    ],
)
def test_api_limits_cannot_expand_beyond_owner_approved_bounds(
    field: str,
    value: int | float,
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values[field] = value

    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)


def test_agent_store_path_cannot_move_into_repository(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values["agent_store_path"] = r"E:\AI\enterprise_ai_platform\agent.sqlite3"

    with pytest.raises(ValidationError, match="approved runtime path"):
        Settings(_env_file=None, **values)


def test_enabled_agent_deadline_may_equal_but_not_exceed_api_deadline(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values.update(
        api_routes_enabled=True,
        agent_enabled=True,
        request_timeout_seconds=25,
    )

    settings = Settings(_env_file=None, **values)
    assert settings.agent_deadline_seconds == settings.request_timeout_seconds == 25

    values["request_timeout_seconds"] = 24
    with pytest.raises(ValidationError, match="must not exceed"):
        Settings(_env_file=None, **values)


def test_telemetry_requires_enabled_api_boundary(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values["telemetry_enabled"] = True

    with pytest.raises(ValidationError, match="W4 API boundary"):
        Settings(_env_file=None, **values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("telemetry_service_name", ""),
        ("telemetry_service_name", "INVALID SERVICE"),
        ("telemetry_service_name", "a" * 65),
        ("telemetry_exporter", "otlp"),
        ("telemetry_otlp_endpoint", "http://127.0.0.1:4317"),
    ],
)
def test_telemetry_rejects_unsafe_or_unapproved_configuration(
    field: str,
    value: object,
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values[field] = value

    with pytest.raises(ValidationError):
        Settings(_env_file=None, **values)
