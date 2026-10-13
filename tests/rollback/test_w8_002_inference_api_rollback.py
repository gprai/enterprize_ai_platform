"""Rollback contract for disabling W8-002 through the existing API switch."""

from __future__ import annotations

from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings


def test_existing_default_off_switch_restores_the_health_only_surface(
    valid_settings: Settings,
) -> None:
    application = create_app(valid_settings)
    paths = {route.path for route in application.routes}
    response = TestClient(application).get("/health")

    assert response.status_code == 200
    assert (
        paths.intersection(
            {"/v1/query", "/v1/agent", "/health/live", "/health/ready", "/_internal/drain"}
        )
        == set()
    )
    assert set(application.state._state) == {"settings"}
    assert valid_settings.api_routes_enabled is False
    assert valid_settings.api_response_streaming_enabled is False
