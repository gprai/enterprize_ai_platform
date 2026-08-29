"""In-process API-to-controller composition without live dependencies."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from enterprise_ai_platform.agent.errors import (
    AgentApprovalConflictError,
    AgentDeadlineError,
    AgentOverloadedError,
    AgentStateUnavailableError,
)
from enterprise_ai_platform.agent.models import (
    AgentOutcome,
    AgentResult,
    TerminalReason,
)
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)
from tests.fakes.agent import FakeAgentController
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe


def _auth(role: Role = Role.READER) -> AuthContext:
    return AuthContext(
        subject_id="agent-user",
        tenant_id="tenant-a",
        roles=frozenset({role}),
        clearance=Classification.INTERNAL,
    )


def _enabled(settings: Settings) -> Settings:
    values = settings.model_dump(mode="python")
    values["agent_enabled"] = True
    return Settings(_env_file=None, **values)


def test_enabled_start_authenticates_and_invokes_controller_exactly_once(
    api_settings: Settings,
) -> None:
    run_id = uuid4()
    controller = FakeAgentController(
        AgentResult(
            request_id=uuid4(),
            run_id=run_id,
            outcome=AgentOutcome.COMPLETED,
            terminal_reason=TerminalReason.ANSWER_REFERENCE_READY,
            result_reference_sha256="a" * 64,
        )
    )
    authenticator = FakeAuthenticator(_auth())
    application = create_app(
        _enabled(api_settings),
        authenticator=authenticator,
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
        agent_controller=controller,
    )
    response = TestClient(application).post(
        "/v1/agent",
        json={"action": "start", "query": "local deterministic request"},
    )

    assert response.status_code == 200
    assert authenticator.calls == 1
    assert len(controller.calls) == 1
    assert controller.calls[0].transport.action == "start"
    assert response.json()["run_id"] == str(run_id)


def test_enabled_unconfigured_controller_fails_closed(api_settings: Settings) -> None:
    application = create_app(
        _enabled(api_settings),
        authenticator=FakeAuthenticator(_auth()),
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
    )
    response = TestClient(application).post(
        "/v1/agent",
        json={"action": "start", "query": "local request"},
    )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "agent_not_configured"


def test_approval_required_returns_202_with_content_free_contract(
    api_settings: Settings,
) -> None:
    approval_id = uuid4()
    run_id = uuid4()
    controller = FakeAgentController(
        AgentResult(
            request_id=uuid4(),
            run_id=run_id,
            approval_id=approval_id,
            outcome=AgentOutcome.APPROVAL_REQUIRED,
            terminal_reason=TerminalReason.APPROVAL_REQUIRED,
        )
    )
    application = create_app(
        _enabled(api_settings),
        authenticator=FakeAuthenticator(_auth(Role.ADMIN)),
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
        agent_controller=controller,
    )
    response = TestClient(application).post(
        "/v1/agent",
        json={"action": "start", "query": "mock write proposal"},
    )

    assert response.status_code == 202
    assert response.json() == {
        "request_id": response.headers["X-Request-ID"],
        "run_id": str(run_id),
        "outcome": "approval_required",
        "terminal_reason": "approval_required",
        "approval_id": str(approval_id),
        "result_reference_sha256": None,
        "safe_error_code": None,
    }


def test_transport_cannot_supply_trusted_authority(api_settings: Settings) -> None:
    controller = FakeAgentController(
        AgentResult(
            request_id=uuid4(),
            run_id=uuid4(),
            outcome=AgentOutcome.SAFE_TERMINAL,
            terminal_reason=TerminalReason.SAFE_FAILURE,
        )
    )
    application = create_app(
        _enabled(api_settings),
        authenticator=FakeAuthenticator(_auth()),
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
        agent_controller=controller,
    )
    response = TestClient(application).post(
        "/v1/agent",
        json={
            "action": "start",
            "query": "request",
            "tenant_id": "attacker",
            "roles": ["admin"],
        },
    )
    assert response.status_code == 422
    assert controller.calls == []


@pytest.mark.parametrize(
    ("failure", "status", "code", "retryable"),
    [
        (AgentApprovalConflictError(), 409, "agent_approval_conflict", None),
        (AgentDeadlineError(), 504, "agent_deadline_exceeded", None),
        (AgentOverloadedError(), 503, "agent_overloaded", True),
        (AgentStateUnavailableError(), 503, "agent_state_unavailable", None),
    ],
)
def test_agent_failures_use_only_approved_safe_api_mappings(
    api_settings: Settings,
    failure: BaseException,
    status: int,
    code: str,
    retryable: bool | None,
) -> None:
    application = create_app(
        _enabled(api_settings),
        authenticator=FakeAuthenticator(_auth()),
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
        agent_controller=FakeAgentController(failure),
    )
    response = TestClient(application).post(
        "/v1/agent",
        json={"action": "start", "query": "safe synthetic request"},
    )

    assert response.status_code == status
    assert response.json()["error"]["code"] == code
    assert response.json()["error"].get("retryable") is retryable
    assert "safe synthetic request" not in response.text
    if isinstance(failure, AgentOverloadedError):
        assert response.headers["Retry-After"] == "1"
