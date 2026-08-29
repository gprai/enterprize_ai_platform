"""Configuration rollback restores the exact W4-001 disabled agent surface."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient
from tests.fakes.agent import FakeAgentController
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe

from enterprise_ai_platform.agent.models import AgentOutcome, AgentResult, TerminalReason
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)


def _settings(settings: Settings, **updates: object) -> Settings:
    values = settings.model_dump(mode="python")
    values.update(updates)
    return Settings(_env_file=None, **values)


def test_disabling_both_agent_flags_restores_exact_501_and_preserves_query_route(
    api_settings: Settings,
) -> None:
    auth = AuthContext(
        subject_id="reader",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )
    controller = FakeAgentController(
        AgentResult(
            request_id=uuid4(),
            run_id=uuid4(),
            outcome=AgentOutcome.COMPLETED,
            terminal_reason=TerminalReason.ANSWER_REFERENCE_READY,
        )
    )
    rolled_back = _settings(
        api_settings,
        agent_enabled=False,
        agent_mock_write_enabled=False,
    )
    application = create_app(
        rolled_back,
        authenticator=FakeAuthenticator(auth),
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
        agent_controller=controller,
    )
    response = TestClient(application).post(
        "/v1/agent",
        json={"action": "start", "query": "ignored"},
    )

    assert response.status_code == 501
    assert response.json()["error"]["code"] == "agent_disabled"
    assert controller.calls == []
    assert str(application.url_path_for("query")) == "/v1/query"
