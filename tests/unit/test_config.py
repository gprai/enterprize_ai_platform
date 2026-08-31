"""Unit tests for typed, fail-fast settings."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.config import Settings

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
    assert settings.api_routes_enabled is False
    assert settings.api_max_request_body_bytes == 131_072
    assert settings.api_readiness_timeout_seconds == 1.0
    assert settings.api_max_inflight_queries == 4
    assert settings.api_query_queue_capacity == 0
    assert settings.telemetry_enabled is False
    assert settings.telemetry_service_name == "enterprise-ai-api"
    assert settings.telemetry_exporter == "none"
    assert settings.telemetry_otlp_endpoint is None
    assert settings.telemetry_span_capacity == 512
    assert settings.telemetry_log_capacity == 512
    assert settings.telemetry_queue_capacity == 0
    assert settings.telemetry_retry_count == 0
    assert settings.telemetry_background_workers == 0
    assert settings.telemetry_flush_timeout_seconds == 1.0
    assert settings.telemetry_shutdown_timeout_seconds == 1.0
    assert settings.agent_enabled is False
    assert settings.agent_mock_write_enabled is False
    assert settings.agent_state_schema_version == "w4-002.agent-state.v1"
    assert settings.agent_graph_version == "w4-002.graph.v1"
    assert settings.agent_store_schema_version == "w4-002.agent-store.v1"
    assert str(settings.agent_store_path) == (
        r"E:\AI\.runtime\enterprise_ai_platform\w4-002\agent-control-v1.sqlite3"
    )
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


@pytest.mark.parametrize("timeout", [0, 121])
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


def test_enabled_agent_deadline_must_remain_inside_api_deadline(
    valid_settings_values: dict[str, object],
) -> None:
    values = dict(valid_settings_values)
    values.update(
        api_routes_enabled=True,
        agent_enabled=True,
        request_timeout_seconds=25,
    )

    with pytest.raises(ValidationError, match="agent deadline"):
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
