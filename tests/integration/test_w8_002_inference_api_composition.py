"""In-process composition coverage for W8-002 admission and failure controls."""

from __future__ import annotations

from fastapi.testclient import TestClient

from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def test_rate_limit_stops_before_the_sixty_first_dependency_call(
    api_settings: Settings,
) -> None:
    rag = FakeRAGService([AbstentionResult(reason="insufficient_evidence") for _ in range(60)])
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=rag,
        readiness_probe=FakeReadinessProbe(),
    )
    client = TestClient(application)

    for request_number in range(60):
        assert (
            client.post(
                "/v1/query",
                json={"query": f"bounded request {request_number}"},
            ).status_code
            == 200
        )
    rejected = client.post("/v1/query", json={"query": "one request too many"})

    assert rejected.status_code == 429
    assert rejected.headers["Retry-After"] == "60"
    assert rejected.json()["error"]["code"] == "api_rate_limited"
    assert len(rag.calls) == 60


def test_five_dependency_failures_open_the_shared_rag_circuit(
    api_settings: Settings,
) -> None:
    rag = FakeRAGService([RuntimeError("private provider error") for _ in range(5)])
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=rag,
        readiness_probe=FakeReadinessProbe(),
    )
    client = TestClient(application, raise_server_exceptions=False)

    for request_number in range(5):
        response = client.post(
            "/v1/query",
            json={"query": f"failure {request_number}"},
        )
        assert response.status_code == 500
        assert "private provider error" not in response.text
    rejected = client.post("/v1/query", json={"query": "blocked by circuit"})

    assert rejected.status_code == 503
    assert rejected.json()["error"]["code"] == "rag_circuit_open"
    assert rejected.headers["Retry-After"] == "30"
    assert len(rag.calls) == 5
