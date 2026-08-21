"""Feature tests proving that W1-002 exposes health only, not RAG behavior."""

from __future__ import annotations

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings


def test_health_is_the_only_business_route(valid_settings: Settings) -> None:
    application = create_app(valid_settings)
    paths = {route.path for route in application.routes}

    assert "/health" in paths
    assert not paths.intersection(
        {
            "/generate",
            "/ingest",
            "/query",
            "/rag",
            "/retrieve",
            "/search",
        }
    )


def test_no_external_client_is_stored_in_application_state(
    valid_settings: Settings,
) -> None:
    application = create_app(valid_settings)
    state_keys = set(application.state._state)

    assert state_keys == {"settings"}
