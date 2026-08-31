"""Security proof that protected values never cross the telemetry allowlist."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from enterprise_ai_platform.agent.controller import BoundedAgentController
from enterprise_ai_platform.agent.errors import AgentAuthorizationError
from enterprise_ai_platform.agent.models import (
    AgentBudgets,
    AnswerReference,
    EvidenceGrade,
    EvidencePacket,
    StartAgentCommand,
)
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.llm.models import Usage
from enterprise_ai_platform.rag.models import CitedAnswerResult
from enterprise_ai_platform.retrieval.models import (
    Answer,
    AuthContext,
    Citation,
    Classification,
    Role,
)
from enterprise_ai_platform.telemetry.models import (
    SafeTelemetryAttributes,
    TelemetryOperation,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import BoundedInMemorySpanExporter
from tests.fakes.agent import (
    FakeAgentGateway,
    FakeAgentPlanner,
    FakeLocalStatusProvider,
    InMemoryAgentStore,
)
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe
from tests.fakes.telemetry import SECURITY_SENTINELS


def _telemetry_enabled(settings: Settings) -> Settings:
    values = settings.model_dump(mode="python")
    values.update(api_routes_enabled=True, telemetry_enabled=True)
    return Settings(_env_file=None, **values)


def _auth(*roles: Role) -> AuthContext:
    return AuthContext(
        subject_id="subject-sensitive-but-never-exported",
        tenant_id="tenant-sensitive-but-never-exported",
        roles=frozenset(roles),
        clearance=Classification.INTERNAL,
    )


def _captured_telemetry(composition) -> str:  # type: ignore[no-untyped-def]
    assert isinstance(composition.span_exporter, BoundedInMemorySpanExporter)
    span_text: list[str] = []
    for span in composition.span_exporter.get_finished_spans():
        span_text.extend((span.name, repr(span.attributes), repr(span.status)))
        span_text.extend(f"{event.name}:{event.attributes!r}" for event in span.events)
    log_text = [record.model_dump_json() for record in composition.log_sink.records()]
    metric_text = repr(composition.metric_reader.get_metrics_data())
    return "\n".join((*span_text, *log_text, metric_text))


def test_all_sentinels_are_absent_from_spans_events_metrics_logs_and_buffers(
    valid_settings: Settings,
    telemetry_factory,
) -> None:  # type: ignore[no-untyped-def]
    composition = telemetry_factory()
    answer = CitedAnswerResult(
        answer=Answer(
            text=" ".join(SECURITY_SENTINELS),
            citations=(
                Citation(
                    source_id="source-001",
                    document_id="document-001",
                    document_version="v1",
                    chunk_id="a" * 64,
                ),
            ),
        ),
        prompt_version="w3-001.v1",
        usage=Usage(input_tokens=2, output_tokens=3, total_tokens=5),
    )
    application = create_app(
        _telemetry_enabled(valid_settings),
        authenticator=FakeAuthenticator(_auth(Role.READER)),
        rag_service=FakeRAGService([answer]),
        readiness_probe=FakeReadinessProbe(),
        telemetry_runtime=composition.runtime,
    )

    response = TestClient(application).post(
        "/v1/query",
        json={"query": " ".join(SECURITY_SENTINELS)},
    )
    assert response.status_code == 200
    composition.runtime.force_flush()

    captured = _captured_telemetry(composition)
    for sentinel in SECURITY_SENTINELS:
        assert sentinel not in captured
    assert "subject-sensitive-but-never-exported" not in captured
    assert "tenant-sensitive-but-never-exported" not in captured


@pytest.mark.parametrize("sentinel", SECURITY_SENTINELS)
def test_allowlist_rejects_sensitive_fields_before_any_sink(sentinel: str) -> None:
    for field in (
        "prompt",
        "answer",
        "evidence",
        "tool_arguments",
        "credential",
        "exception_message",
        "tenant_id",
        "subject_id",
        "approval_id",
        "run_id",
    ):
        with pytest.raises(ValidationError):
            SafeTelemetryAttributes(
                stage=TelemetryStage.API,
                operation=TelemetryOperation.REQUEST,
                **{field: sentinel},
            )


def test_authorization_denial_stops_before_graph_gateway_planner_or_tool(
    telemetry_factory,
) -> None:  # type: ignore[no-untyped-def]
    composition = telemetry_factory()
    gateway = FakeAgentGateway(
        evidence=EvidencePacket(references=("a" * 64,)),
        grade=EvidenceGrade(authorized=True, sufficient=True),
        answer=AnswerReference(result_reference_sha256="b" * 64, total_tokens=1),
    )
    planner = FakeAgentPlanner(None)
    status = FakeLocalStatusProvider()
    store = InMemoryAgentStore()
    controller = BoundedAgentController(
        gateway=gateway,
        planner=planner,
        status_provider=status,
        store=store,
        budgets=AgentBudgets(),
        mock_write_enabled=False,
        telemetry=composition.runtime,
    )

    with pytest.raises(AgentAuthorizationError):
        asyncio.run(
            controller.handle(
                StartAgentCommand(query="must stop before work"),
                _auth(Role.REVIEWER),
                str(uuid4()),
            )
        )

    assert gateway.calls == []
    assert planner.calls == 0
    assert status.calls == 0
    assert store.states == []
    assert store.approvals == {}
