"""Feature proof for readiness withdrawal and the non-streaming API contract."""

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


def test_loopback_drain_withdraws_readiness_and_rejects_new_model_work(
    api_settings: Settings,
) -> None:
    rag = FakeRAGService([AbstentionResult(reason="insufficient_evidence")])
    application = create_app(
        api_settings,
        authenticator=FakeAuthenticator(_auth()),
        rag_service=rag,
        readiness_probe=FakeReadinessProbe(),
    )
    client = TestClient(application, client=("127.0.0.1", 50000))

    first = client.post("/v1/query", json={"query": "before drain"})
    drained = client.post("/_internal/drain")
    readiness = client.get("/health/ready")
    rejected = client.post("/v1/query", json={"query": "after drain"})
    repeated = client.post("/_internal/drain")

    assert first.status_code == 200
    assert first.headers["content-type"] == "application/json"
    assert "transfer-encoding" not in first.headers
    assert drained.status_code == 200
    assert drained.json()["status"] == "draining"
    assert readiness.status_code == 503
    assert readiness.json()["error"]["code"] == "service_not_ready"
    assert rejected.status_code == 503
    assert rejected.json()["error"]["code"] == "api_draining"
    assert repeated.status_code == 200
    assert len(rag.calls) == 1
