"""Rollback proof for disabling only the W4-001 route surface."""

from __future__ import annotations

from pathlib import Path

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

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PROTECTED_RAG_IDENTITIES = (
    REPOSITORY_ROOT / "configs" / "rag.yaml",
    REPOSITORY_ROOT / "configs" / "rag" / "versions" / "w3-002-v1.json",
    REPOSITORY_ROOT
    / "configs"
    / "rag"
    / "versions"
    / "w3-004-synthetic-regression-v1.json",
)


def _auth() -> AuthContext:
    return AuthContext(
        subject_id="reader-a",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )


def test_default_off_restores_exact_health_only_business_surface(
    valid_settings: Settings,
) -> None:
    before = {path: path.read_bytes() for path in PROTECTED_RAG_IDENTITIES}
    authenticator = FakeAuthenticator(_auth())
    rag = FakeRAGService([AbstentionResult(reason="insufficient_evidence")])
    readiness = FakeReadinessProbe()

    application = create_app(
        valid_settings,
        authenticator=authenticator,
        rag_service=rag,
        readiness_probe=readiness,
    )
    paths = {route.path for route in application.routes}
    response = TestClient(application).get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "enterprise-ai-platform",
        "environment": "sandbox",
    }
    assert "X-Request-ID" not in response.headers
    assert "/health" in paths
    assert not paths.intersection(
        {"/health/live", "/health/ready", "/v1/query", "/v1/agent"}
    )
    assert set(application.state._state) == {"settings"}
    assert authenticator.calls == 0
    assert rag.calls == []
    assert readiness.calls == 0
    assert {path: path.read_bytes() for path in PROTECTED_RAG_IDENTITIES} == before
