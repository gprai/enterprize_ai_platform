from __future__ import annotations

from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe


def test_local_application_health_and_readiness_need_no_external_provider(
    api_settings: Settings,
) -> None:
    auth = AuthContext(
        subject_id="smoke-reader",
        tenant_id="smoke-tenant",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(auth),
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
    )

    with TestClient(application) as client:
        health = client.get("/health")
        ready = client.get("/health/ready")

    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"
