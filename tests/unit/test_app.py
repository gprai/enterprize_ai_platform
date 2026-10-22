"""Unit tests for the minimal FastAPI application factory."""

from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient

import enterprise_ai_platform.app as app_module
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.telemetry.runtime import NullTelemetryRuntime


class FakeAWSRuntime:
    def __init__(self, *, startup_error: Exception | None = None) -> None:
        self.rag_service = object()
        self.readiness_probe = object()
        self.telemetry = NullTelemetryRuntime()
        self.startup_error = startup_error
        self.events: list[str] = []

    async def start(self) -> None:
        self.events.append("start")
        if self.startup_error is not None:
            raise self.startup_error

    async def close(self) -> None:
        self.events.append("close")


def _aws_settings(settings: Settings) -> Settings:
    return settings.model_copy(
        update={
            "aws_composition_enabled": True,
            "telemetry_enabled": True,
        }
    )


def test_health_response_contains_only_non_sensitive_fields(
    valid_settings: Settings,
) -> None:
    client = TestClient(create_app(valid_settings))
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "enterprise-ai-platform",
        "environment": "sandbox",
    }


def test_application_factory_does_not_open_network_connections(
    monkeypatch: pytest.MonkeyPatch,
    valid_settings: Settings,
) -> None:
    def reject_connection(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("application construction attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", reject_connection)
    application = create_app(valid_settings)

    assert application.state.settings is valid_settings


def test_aws_embedding_warmup_completes_before_application_serves(
    monkeypatch: pytest.MonkeyPatch,
    valid_settings: Settings,
) -> None:
    runtime = FakeAWSRuntime()
    monkeypatch.setattr(
        app_module,
        "compose_aws_runtime",
        lambda _settings: runtime,
    )

    application = create_app(_aws_settings(valid_settings))

    with TestClient(application) as client:
        assert runtime.events == ["start"]
        assert client.get("/health").status_code == 200

    assert runtime.events == ["start", "close"]


def test_aws_embedding_warmup_failure_prevents_application_startup(
    monkeypatch: pytest.MonkeyPatch,
    valid_settings: Settings,
) -> None:
    runtime = FakeAWSRuntime(startup_error=RuntimeError("warmup failed"))
    monkeypatch.setattr(
        app_module,
        "compose_aws_runtime",
        lambda _settings: runtime,
    )

    application = create_app(_aws_settings(valid_settings))

    with pytest.raises(RuntimeError, match="warmup failed"):
        with TestClient(application):
            pass

    assert runtime.events == ["start", "close"]


def test_workload_probe_fails_without_regular_authenticator(valid_settings: Settings) -> None:
    settings = valid_settings.model_copy(
        update={
            "workload_probe_auth_enabled": True,
            "workload_probe_issuer": "https://issuer.example.invalid",
            "workload_probe_tenant_id": "approved-tenant",
            "capstone_tls_enabled": True,
            "capstone_tls_root_fingerprint_sha256": "a" * 64,
        }
    )
    with pytest.raises(ValueError, match="approved regular authenticator"):
        create_app(settings)
