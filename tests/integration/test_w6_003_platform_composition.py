from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient
from tools import w6_003_readiness

from enterprise_ai_platform.agent.models import AgentOutcome, AgentResult, TerminalReason
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.rag.models import AbstentionResult
from enterprise_ai_platform.retrieval.models import AuthContext, Classification, Role
from tests.fakes import readiness
from tests.fakes.agent import FakeAgentController
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe


def _settings(api_settings: Settings) -> Settings:
    values = api_settings.model_dump(mode="python")
    values["agent_enabled"] = True
    values["telemetry_enabled"] = True
    return Settings(_env_file=None, **values)


def test_api_rag_agent_telemetry_and_handover_compose_without_network(
    api_settings: Settings,
    telemetry_factory,
) -> None:  # type: ignore[no-untyped-def]
    auth = AuthContext(
        subject_id="local-reader",
        tenant_id="local-tenant",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )
    composition = telemetry_factory()
    controller = FakeAgentController(
        AgentResult(
            request_id=uuid4(),
            run_id=uuid4(),
            outcome=AgentOutcome.COMPLETED,
            terminal_reason=TerminalReason.ANSWER_REFERENCE_READY,
            result_reference_sha256="a" * 64,
        )
    )
    application = create_app(
        _settings(api_settings),
        authenticator=FakeAuthenticator(auth),
        rag_service=FakeRAGService([AbstentionResult(reason="insufficient_evidence")]),
        readiness_probe=FakeReadinessProbe(),
        agent_controller=controller,
        telemetry_runtime=composition.runtime,
    )

    with TestClient(application) as client:
        readiness_response = client.get("/health/ready")
        query_response = client.post("/v1/query", json={"query": "local bounded query"})
        agent_response = client.post(
            "/v1/agent",
            json={"action": "start", "query": "local bounded agent request"},
        )

    assert readiness_response.status_code == 200
    assert query_response.status_code == 200
    assert query_response.json()["outcome"] == "abstained"
    assert agent_response.status_code == 200
    assert len(controller.calls) == 1
    assert composition.runtime.force_flush() is True

    proof = readiness.local_proof()
    rollback = readiness.local_rollback()
    w6_003_readiness.validate_handover(
        readiness.handover(proof, rollback),
        local_proof_sha256=w6_003_readiness.sha256_bytes(
            w6_003_readiness.canonical_json_bytes(proof)
        ),
        local_rollback_sha256=w6_003_readiness.sha256_bytes(
            w6_003_readiness.canonical_json_bytes(rollback)
        ),
        now=readiness.NOW,
    )
