"""Typed, fail-fast runtime configuration."""

from __future__ import annotations

import os
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
WINDOWS_AGENT_STORE_PATH = r"E:\AI\.runtime\enterprise_ai_platform\w4-002\agent-control-v1.sqlite3"
LINUX_AGENT_STORE_PATH = "/var/lib/enterprise-ai-platform/w4-002/agent-control-v1.sqlite3"
AGENT_STORE_PATH = Path(WINDOWS_AGENT_STORE_PATH if os.name == "nt" else LINUX_AGENT_STORE_PATH)
W6_004_EMBEDDING_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"  # pragma: allowlist secret
W6_004_EMBEDDING_SNAPSHOT_PATH = Path(
    f"/app/enterprise_ai_platform/models/{W6_004_EMBEDDING_REVISION}"
)
SANDBOX_AUTH_SIGNING_KEY_FILE_PATH = Path("/var/run/secrets/enterprise-ai/sandbox-auth-signing-key")
MAX_SECRET_FILE_BYTES = 4096


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
    sandbox_auth_enabled: bool = False
    sandbox_auth_issuer: str | None = Field(default=None, min_length=1, max_length=200)
    sandbox_auth_audience: str | None = Field(default=None, min_length=1, max_length=200)
    sandbox_auth_tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    sandbox_auth_signing_key: SecretStr | None = None
    sandbox_auth_signing_key_file: Path | None = None
    aws_composition_enabled: bool = False
    embedding_snapshot_path: Path = W6_004_EMBEDDING_SNAPSHOT_PATH
    opensearch_index_name: Literal["enterprise_ai_sandbox"] = "enterprise_ai_sandbox"
    telemetry_enabled: bool = False
    telemetry_service_name: str = Field(
        default="enterprise-ai-api",
        min_length=1,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9._-]*$",
    )
    telemetry_exporter: Literal["none", "otlp_grpc"] = "none"
    telemetry_otlp_endpoint: str | None = Field(default=None, max_length=64)
    telemetry_span_capacity: Literal[512] = 512
    telemetry_log_capacity: Literal[512] = 512
    telemetry_queue_capacity: Literal[0, 512] = 0
    telemetry_batch_size: Literal[0, 64] = 0
    telemetry_export_delay_seconds: float = Field(default=0.0, ge=0.0, le=1.0)
    telemetry_export_timeout_seconds: float = Field(default=0.0, ge=0.0, le=1.0)
    telemetry_retry_count: Literal[0] = 0
    telemetry_background_workers: Literal[0, 1] = 0
    telemetry_flush_timeout_seconds: float = Field(default=1.0, ge=1.0, le=2.0)
    telemetry_shutdown_timeout_seconds: float = Field(
        default=1.0,
        ge=1.0,
        le=2.0,
    )
    agent_enabled: bool = False
    agent_mock_write_enabled: bool = False
    agent_state_schema_version: Literal["w4-002.agent-state.v1"] = "w4-002.agent-state.v1"
    agent_graph_version: Literal["w4-002.graph.v1"] = "w4-002.graph.v1"
    agent_store_schema_version: Literal["w4-002.agent-store.v1"] = "w4-002.agent-store.v1"
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
    def normalize_telemetry_endpoint(cls, value: object) -> object:
        """Normalize an optional endpoint before exact profile validation."""

        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        return value

    @field_validator(
        "telemetry_queue_capacity",
        "telemetry_batch_size",
        "telemetry_background_workers",
        mode="before",
    )
    @classmethod
    def normalize_telemetry_integer_literal(cls, value: object) -> object:
        """Parse only the exact integer strings supplied by Kubernetes env vars."""

        if isinstance(value, str) and value in {"0", "1", "64", "512"}:
            return int(value)
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

    @field_validator("sandbox_auth_signing_key", mode="before")
    @classmethod
    def reject_sandbox_auth_placeholder(cls, value: object) -> object:
        if value is None or (isinstance(value, str) and not value.strip()):
            return None
        if isinstance(value, str) and value.strip() in {TODO_MARKER, "OWNER_BINDING_REQUIRED"}:
            raise ValueError("sandbox auth signing key must be externally supplied")
        return value

    @field_validator("sandbox_auth_signing_key_file")
    @classmethod
    def require_exact_sandbox_auth_signing_key_file(cls, value: Path | None) -> Path | None:
        if value is not None and value != SANDBOX_AUTH_SIGNING_KEY_FILE_PATH:
            raise ValueError("sandbox auth signing key file must use the approved mounted path")
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

        if (
            self.sandbox_auth_signing_key is not None
            and self.sandbox_auth_signing_key_file is not None
        ):
            raise ValueError("sandbox auth signing key must use exactly one delivery source")
        if self.sandbox_auth_signing_key_file is not None:
            try:
                secret_bytes = self.sandbox_auth_signing_key_file.read_bytes()
            except OSError as exc:
                raise ValueError("sandbox auth signing key file is unreadable") from exc
            if not secret_bytes or len(secret_bytes) > MAX_SECRET_FILE_BYTES:
                raise ValueError("sandbox auth signing key file size is invalid")
            try:
                secret_value = secret_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError("sandbox auth signing key file must be UTF-8") from exc
            if secret_value != secret_value.strip():
                raise ValueError("sandbox auth signing key file must not contain outer whitespace")
            self.sandbox_auth_signing_key = SecretStr(secret_value)

        if self.llm_provider == "bedrock" and (
            self.llm_model_id is None or self.aws_region is None
        ):
            raise ValueError("Bedrock requires llm_model_id and aws_region")
        if self.sandbox_auth_enabled:
            if (
                self.sandbox_auth_issuer is None
                or self.sandbox_auth_audience is None
                or self.sandbox_auth_tenant_id is None
                or self.sandbox_auth_signing_key is None
                or len(self.sandbox_auth_signing_key.get_secret_value().encode()) < 32
            ):
                raise ValueError(
                    "sandbox auth requires issuer, audience, tenant, and a 32-byte key"
                )
        if self.aws_composition_enabled:
            opensearch_host = self.opensearch_url.host or ""
            if (
                not self.api_routes_enabled
                or not self.sandbox_auth_enabled
                or not self.telemetry_enabled
                or self.telemetry_exporter != "otlp_grpc"
                or self.llm_provider != "bedrock"
                or self.aws_region != "ap-southeast-1"
                or self.llm_model_id in {None, "OWNER_BINDING_REQUIRED"}
                or self.opensearch_url.scheme != "https"
                or not opensearch_host.endswith(".ap-southeast-1.es.amazonaws.com")
                or not self.embedding_snapshot_path.is_absolute()
                or self.embedding_snapshot_path.name != W6_004_EMBEDDING_REVISION
            ):
                raise ValueError("AWS composition requires the exact owner-bound W6-004 profile")
        if not self.agent_store_path.is_absolute():
            raise ValueError("agent_store_path must be absolute")
        if self.agent_enabled and self.agent_deadline_seconds >= self.request_timeout_seconds:
            raise ValueError("agent deadline must remain inside the API deadline")
        if self.telemetry_enabled and not self.api_routes_enabled:
            raise ValueError("enabled telemetry requires the W4 API boundary")
        disabled_profile = (
            self.telemetry_otlp_endpoint is None
            and self.telemetry_queue_capacity == 0
            and self.telemetry_batch_size == 0
            and self.telemetry_export_delay_seconds == 0.0
            and self.telemetry_export_timeout_seconds == 0.0
            and self.telemetry_retry_count == 0
            and self.telemetry_background_workers == 0
            and self.telemetry_flush_timeout_seconds == 1.0
            and self.telemetry_shutdown_timeout_seconds == 1.0
        )
        exporting_profile = (
            self.telemetry_enabled
            and self.telemetry_otlp_endpoint == "http://127.0.0.1:4317"
            and self.telemetry_queue_capacity == 512
            and self.telemetry_batch_size == 64
            and self.telemetry_export_delay_seconds == 1.0
            and self.telemetry_export_timeout_seconds == 1.0
            and self.telemetry_retry_count == 0
            and self.telemetry_background_workers == 1
            and self.telemetry_flush_timeout_seconds == 2.0
            and self.telemetry_shutdown_timeout_seconds == 2.0
        )
        if self.telemetry_exporter == "none" and not disabled_profile:
            raise ValueError("disabled telemetry export requires the exact zero-worker profile")
        if self.telemetry_exporter == "otlp_grpc" and not exporting_profile:
            raise ValueError("otlp_grpc requires the exact approved loopback export profile")
        return self
