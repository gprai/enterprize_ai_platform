"""Typed, fail-fast runtime configuration."""

from __future__ import annotations

from ipaddress import IPv4Address
from pathlib import Path
from typing import Literal

from pydantic import (
    AnyHttpUrl,
    Field,
    IPvAnyAddress,
    SecretStr,
    ValidationInfo,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

TODO_MARKER = "TODO_USER"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
AGENT_STORE_PATH = Path(
    r"E:\AI\.runtime\enterprise_ai_platform\w4-002\agent-control-v1.sqlite3"
)


class Settings(BaseSettings):
    """Environment-backed settings with no usable external-service defaults."""

    model_config = SettingsConfigDict(
        env_prefix="ENTERPRISE_AI_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="forbid",
        validate_default=True,
    )

    app_name: str = Field(default="enterprise-ai-platform", min_length=1, max_length=100)
    environment: Literal["sandbox"] = "sandbox"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    host: IPvAnyAddress = IPv4Address("127.0.0.1")
    port: int = Field(default=8000, ge=1, le=65535)
    request_timeout_seconds: int = Field(default=30, ge=1, le=120)
    api_routes_enabled: bool = False
    api_max_request_body_bytes: int = Field(default=131_072, ge=1, le=131_072)
    api_readiness_timeout_seconds: float = Field(default=1.0, gt=0, le=1.0)
    api_max_inflight_queries: int = Field(default=4, ge=1, le=4)
    api_query_queue_capacity: Literal[0] = 0
    telemetry_enabled: bool = False
    telemetry_service_name: str = Field(
        default="enterprise-ai-api",
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    telemetry_exporter: Literal["none"] = "none"
    telemetry_otlp_endpoint: None = None
    telemetry_span_capacity: Literal[512] = 512
    telemetry_log_capacity: Literal[512] = 512
    telemetry_queue_capacity: Literal[0] = 0
    telemetry_retry_count: Literal[0] = 0
    telemetry_background_workers: Literal[0] = 0
    telemetry_flush_timeout_seconds: float = Field(default=1.0, ge=1.0, le=1.0)
    telemetry_shutdown_timeout_seconds: float = Field(
        default=1.0,
        ge=1.0,
        le=1.0,
    )
    agent_enabled: bool = False
    agent_mock_write_enabled: bool = False
    agent_state_schema_version: Literal["w4-002.agent-state.v1"] = (
        "w4-002.agent-state.v1"
    )
    agent_graph_version: Literal["w4-002.graph.v1"] = "w4-002.graph.v1"
    agent_store_schema_version: Literal["w4-002.agent-store.v1"] = (
        "w4-002.agent-store.v1"
    )
    agent_store_path: Path = AGENT_STORE_PATH
    agent_approval_ttl_seconds: Literal[600] = 600
    agent_terminal_retention_seconds: Literal[86_400] = 86_400
    agent_maximum_graph_steps: Literal[8] = 8
    agent_maximum_tool_calls: Literal[1] = 1
    agent_maximum_provider_attempts: Literal[1] = 1
    agent_maximum_total_tokens: Literal[4096] = 4096
    agent_graph_retries: Literal[0] = 0
    agent_deadline_seconds: Literal[25] = 25
    agent_maximum_serialized_state_bytes: Literal[16_384] = 16_384
    agent_maximum_concurrent_runs: Literal[1] = 1
    agent_queue_capacity: Literal[0] = 0

    llm_provider: Literal["fake", "bedrock"] = "fake"
    llm_model_id: str | None = Field(default=None, min_length=1, max_length=200)
    aws_region: str | None = Field(
        default=None,
        min_length=1,
        pattern=r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$",
    )
    embedding_model_id: str = Field(min_length=1, max_length=200)
    qdrant_url: AnyHttpUrl
    opensearch_url: AnyHttpUrl
    qdrant_api_key: SecretStr | None = None

    @field_validator(
        "embedding_model_id",
        "qdrant_url",
        "opensearch_url",
        mode="before",
    )
    @classmethod
    def reject_unresolved_values(cls, value: object) -> object:
        """Reject copied placeholders before runtime clients can be configured."""
        if isinstance(value, str) and value.strip().casefold() == TODO_MARKER.casefold():
            raise ValueError(f"{TODO_MARKER} must be replaced before runtime use")
        return value

    @field_validator("llm_model_id", "aws_region", mode="before")
    @classmethod
    def normalize_optional_llm_value(cls, value: object) -> object:
        """Treat blanks as absent and reject unresolved LLM placeholders."""

        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                return None
            if normalized.casefold() == TODO_MARKER.casefold():
                raise ValueError(f"{TODO_MARKER} must be replaced before runtime use")
            return normalized
        return value

    @field_validator("telemetry_otlp_endpoint", mode="before")
    @classmethod
    def normalize_disabled_telemetry_endpoint(cls, value: object) -> object:
        """Allow only an absent or blank endpoint in the default-off boundary."""

        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return value

    @field_validator("qdrant_api_key", mode="before")
    @classmethod
    def normalize_optional_secret(cls, value: object) -> object:
        """Treat a blank local API key as absent and reject placeholders."""
        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                return None
            if normalized.casefold() == TODO_MARKER.casefold():
                raise ValueError(f"{TODO_MARKER} is not a secret value")
        return value

    @field_validator("agent_store_path")
    @classmethod
    def require_exact_agent_store_path(cls, value: Path) -> Path:
        if value != AGENT_STORE_PATH:
            raise ValueError("agent_store_path must match the approved runtime path")
        return value

    @field_validator("qdrant_url", "opensearch_url")
    @classmethod
    def require_secure_external_urls(
        cls,
        value: AnyHttpUrl,
        info: ValidationInfo,
    ) -> AnyHttpUrl:
        """Allow HTTP only for explicitly local loopback services."""
        if value.scheme == "http" and value.host not in LOOPBACK_HOSTS:
            raise ValueError(f"{info.field_name} must use HTTPS outside loopback")
        return value

    @model_validator(mode="after")
    def require_bedrock_configuration(self) -> Settings:
        """Require explicit model and region only when Bedrock is selected."""

        if self.llm_provider == "bedrock" and (
            self.llm_model_id is None or self.aws_region is None
        ):
            raise ValueError("Bedrock requires llm_model_id and aws_region")
        if not self.agent_store_path.is_absolute():
            raise ValueError("agent_store_path must be absolute")
        if (
            self.agent_enabled
            and self.agent_deadline_seconds >= self.request_timeout_seconds
        ):
            raise ValueError("agent deadline must remain inside the API deadline")
        if self.telemetry_enabled and not self.api_routes_enabled:
            raise ValueError("enabled telemetry requires the W4 API boundary")
        return self
