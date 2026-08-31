"""Rollback proof for disabling W4-003 telemetry without business-path change."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)
from enterprise_ai_platform.telemetry.runtime import NullTelemetryRuntime


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def _api_enabled(settings: Settings) -> Settings:
    values = settings.model_dump(mode="python")
    values["api_routes_enabled"] = True
    return Settings(_env_file=None, **values)


def test_default_off_preserves_exact_health_only_foundation(
    valid_settings: Settings,
) -> None:
    application = create_app(valid_settings)
    response = TestClient(application).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "enterprise-ai-platform",
        "environment": "sandbox",
    }
    assert "X-Request-ID" not in response.headers
    assert set(application.state._state) == {"settings"}


def test_disabled_telemetry_preserves_query_abstention_and_security_contract(
    valid_settings: Settings,
) -> None:
    settings = _api_enabled(valid_settings)
    rag = FakeRAGService([AbstentionResult(reason="insufficient_evidence", usage=None)])
    authenticator = FakeAuthenticator(_auth())
    application = create_app(
        settings,
        authenticator=authenticator,
        rag_service=rag,
        readiness_probe=FakeReadinessProbe(),
    )

    response = TestClient(application).post(
        "/v1/query",
        json={"query": "bounded local request"},
    )

    assert response.status_code == 200
    assert response.json()["outcome"] == "abstained"
    assert response.json()["reason"] == "insufficient_evidence"
    assert authenticator.calls == 1
    assert len(rag.calls) == 1
    assert isinstance(
        application.state.telemetry_runtime,
        NullTelemetryRuntime,
    )


def test_disabled_or_unconfigured_active_telemetry_fails_before_app_start(
    valid_settings: Settings,
) -> None:
    with pytest.raises(ValueError, match="disabled telemetry"):
        create_app(valid_settings, telemetry_runtime=NullTelemetryRuntime())

    values = valid_settings.model_dump(mode="python")
    values.update(api_routes_enabled=True, telemetry_enabled=True)
    enabled = Settings(_env_file=None, **values)
    with pytest.raises(ValueError, match="requires an injected runtime"):
        create_app(enabled)
