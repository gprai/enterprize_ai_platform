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
