"""Security and privacy coverage for W8-002 operational controls."""

from __future__ import annotations

from fastapi.testclient import TestClient

from enterprise_ai_platform.api.runtime import TenantRateLimiter
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-private-value",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def test_internal_drain_is_loopback_only(api_settings: Settings) -> None:
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=FakeRAGService([AbstentionResult(reason="insufficient_evidence")]),
        readiness_probe=FakeReadinessProbe(),
    )
    client = TestClient(application, client=("203.0.113.10", 50000))

    response = client.post("/_internal/drain")

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "authorization_denied"
    assert application.state.api_drain_controller.is_draining is False


def test_rate_limit_state_retains_only_tenant_digests() -> None:
    limiter = TenantRateLimiter(
        maximum_requests=60,
        window_seconds=60,
        maximum_tenants=1024,
    )

    assert limiter.try_consume("tenant-private-value") == (True, 0)
    assert "tenant-private-value" not in repr(limiter._windows)  # noqa: SLF001
