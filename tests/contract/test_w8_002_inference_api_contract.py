"""Contract coverage for the exact W8-002 inference API surface."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.api.models import DrainResponse, QueryRequest
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings


def test_query_and_drain_schemas_are_strict_bounded_and_content_free() -> None:
    assert QueryRequest.model_json_schema()["properties"]["query"]["maxLength"] == 10_000
    assert QueryRequest.model_json_schema()["properties"]["query"]["minLength"] == 1
    assert set(DrainResponse.model_json_schema()["properties"]) == {
        "request_id",
        "status",
        "completed_requests",
        "cancelled_requests",
    }
    with pytest.raises(ValidationError):
        QueryRequest(query="x" * 10_001)


def test_enabled_service_has_one_query_route_and_no_streaming_route(
    api_settings: Settings,
) -> None:
    application = create_app(api_settings)
    paths = application.openapi()["paths"]

    assert list(paths).count("/v1/query") == 1
    assert "/_internal/drain" not in paths
    assert not any("stream" in path.casefold() for path in paths)
    assert api_settings.api_response_streaming_enabled is False
    assert api_settings.api_retry_attempts == 0
