"""Unit tests for the minimal FastAPI application factory."""

from __future__ import annotations

import socket

import pytest
from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings


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
