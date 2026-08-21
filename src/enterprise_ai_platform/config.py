"""Typed, fail-fast runtime configuration."""

from __future__ import annotations

from ipaddress import IPv4Address
from typing import Literal

from pydantic import (
    AnyHttpUrl,
    Field,
    IPvAnyAddress,
    SecretStr,
    ValidationInfo,
    field_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

TODO_MARKER = "TODO_USER"
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


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

    aws_region: str = Field(
        min_length=1,
        pattern=r"^[a-z]{2}(?:-gov)?-[a-z]+-\d+$",
    )
    embedding_model_id: str = Field(min_length=1, max_length=200)
    qdrant_url: AnyHttpUrl
    opensearch_url: AnyHttpUrl
    qdrant_api_key: SecretStr | None = None

    @field_validator(
        "aws_region",
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
