"""Deterministic W4-09 safe-failure, redaction, and cleanup proof."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from enterprise_ai_platform.agent.controller import BoundedAgentController
from enterprise_ai_platform.agent.errors import (
    AgentAuthorizationError,
    AgentOverloadedError,
)
from enterprise_ai_platform.agent.graph import (
    AgentRunContext,
    build_agent_graph,
    initial_graph_state,
)
from enterprise_ai_platform.agent.models import (
    AgentBudgets,
    AgentOutcome,
    AgentResult,
    AnswerReference,
    ApprovalRecord,
    ApprovalStatus,
    DecideAgentCommand,
    EvidenceGrade,
    EvidencePacket,
    MockSetServiceModeArguments,
    StartAgentCommand,
    TerminalReason,
    ToolKind,
    ToolProposal,
)
from enterprise_ai_platform.agent.runtime import DeadlineClock
from enterprise_ai_platform.agent.tools import ToolRegistry
from enterprise_ai_platform.app import create_app
from enterprise_ai_platform.config import Settings
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)
from enterprise_ai_platform.telemetry.runtime import (
    BoundedInMemorySpanExporter,
    TelemetryRuntime,
    build_in_memory_telemetry,
)
from tests.fakes.agent import (
    FakeAgentController,
    FakeAgentGateway,
    FakeAgentPlanner,
    FakeLocalStatusProvider,
    InMemoryAgentStore,
)
from tests.fakes.api import FakeAuthenticator, FakeRAGService, FakeReadinessProbe
from tests.fakes.telemetry import (
    SECURITY_SENTINELS,
    DeterministicClock,
    FailingSpanExporter,
)
from tests.security.test_api_authorization import INJECTION, SECRET


def _auth(subject: str, *roles: Role) -> AuthContext:
    return AuthContext(
        subject_id=subject,
        tenant_id="tenant-a",
        roles=frozenset(roles),
        clearance=Classification.INTERNAL,
    )


def _gateway() -> FakeAgentGateway:
    return FakeAgentGateway(
        evidence=EvidencePacket(references=("a" * 64,)),
        grade=EvidenceGrade(authorized=True, sufficient=True),
        answer=AnswerReference(
            result_reference_sha256="b" * 64,
            total_tokens=5,
        ),
    )


def _controller(
    *,
    proposal: ToolProposal | None = None,
    budgets: AgentBudgets | None = None,
    telemetry: TelemetryRuntime | None = None,
    mock_write_enabled: bool = False,
) -> tuple[
    BoundedAgentController,
    FakeAgentGateway,
    FakeAgentPlanner,
    FakeLocalStatusProvider,
    InMemoryAgentStore,
]:
    gateway = _gateway()
    planner = FakeAgentPlanner(proposal)
    status = FakeLocalStatusProvider()
    store = InMemoryAgentStore()
    controller = BoundedAgentController(
        gateway=gateway,
        planner=planner,
        status_provider=status,
        store=store,
        budgets=budgets or AgentBudgets(),
        mock_write_enabled=mock_write_enabled,
        telemetry=telemetry,
    )
    return controller, gateway, planner, status, store


def _run_graph(
    *,
    budgets: AgentBudgets,
    clock: DeadlineClock,
) -> tuple[
    object,
    FakeAgentGateway,
    FakeAgentPlanner,
    FakeLocalStatusProvider,
    InMemoryAgentStore,
]:
    auth_context = _auth("reader", Role.READER)
    gateway = _gateway()
    planner = FakeAgentPlanner(None)
    status = FakeLocalStatusProvider()
    store = InMemoryAgentStore()
    request_id = uuid4()
    run_id = uuid4()
    result = asyncio.run(
        build_agent_graph().ainvoke(
            initial_graph_state(
                request_id=request_id,
                run_id=run_id,
                auth_context=auth_context,
            ),
            context=AgentRunContext(
                query="bounded request",
                auth_context=auth_context,
                request_id=request_id,
                run_id=run_id,
                gateway=gateway,
                planner=planner,
                registry=ToolRegistry(status, mock_write_enabled=False),
                store=store,
                budgets=budgets,
                clock=clock,
                approval_ttl_seconds=600,
            ),
        )
    )["control"]
    return result, gateway, planner, status, store


def _write_proposal() -> ToolProposal:
    return ToolProposal(
        name="mock_set_service_mode",
        kind=ToolKind.MOCK_WRITE,
        arguments=MockSetServiceModeArguments(mode="maintenance"),
    )


def _decision(approval_id: object) -> DecideAgentCommand:
    return DecideAgentCommand(
        approval_id=approval_id,
        idempotency_key=uuid4(),
        tool_name="mock_set_service_mode",
        tool_version="1.0",
        arguments=MockSetServiceModeArguments(mode="maintenance"),
    )


def test_denial_stops_before_gateway_planner_store_or_tool_activity() -> None:
    controller, gateway, planner, status, store = _controller()

    with pytest.raises(AgentAuthorizationError) as raised:
        asyncio.run(
            controller.handle(
                StartAgentCommand(query="authorization boundary"),
                _auth("reviewer", Role.REVIEWER),
                str(uuid4()),
            )
        )

    assert raised.value.code == "authorization_denied"
    assert gateway.calls == []
    assert planner.calls == 0
    assert status.calls == 0
    assert store.states == []
    assert store.approvals == {}
    assert controller.active_runs == 0


def test_malformed_tool_arguments_stop_before_authenticator_controller_or_tool(
    agent_settings: Settings,
) -> None:
    authenticator = FakeAuthenticator(_auth("reviewer", Role.REVIEWER))
    controller = FakeAgentController(
        AgentResult(
            request_id=uuid4(),
            run_id=uuid4(),
            outcome=AgentOutcome.SAFE_TERMINAL,
            terminal_reason=TerminalReason.SAFE_FAILURE,
        )
    )
    application = create_app(
        agent_settings,
        authenticator=authenticator,
        rag_service=FakeRAGService(()),
        readiness_probe=FakeReadinessProbe(),
        agent_controller=controller,
    )

    with TestClient(application) as client:
        response = client.post(
            "/v1/agent",
            json={
                "action": "decide",
                "approval_id": str(uuid4()),
                "idempotency_key": str(uuid4()),
                "decision": "approved",
                "tool_name": "mock_set_service_mode",
                "tool_version": "1.0",
                "arguments": {
                    "mode": "maintenance",
                    "unexpected": SECURITY_SENTINELS[3],
                },
            },
        )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "api_request_invalid"
    assert SECURITY_SENTINELS[3] not in response.text
    assert authenticator.calls == 0
    assert controller.calls == []


def test_prompt_injection_remains_data_and_cannot_invoke_a_tool(
    caplog: pytest.LogCaptureFixture,
) -> None:
    controller, gateway, planner, status, _ = _controller()

    result = asyncio.run(
        controller.handle(
            StartAgentCommand(query=INJECTION),
            _auth("reader", Role.READER),
            str(uuid4()),
        )
    )

    assert result.outcome is AgentOutcome.COMPLETED
    assert result.terminal_reason is TerminalReason.ANSWER_REFERENCE_READY
    assert gateway.calls == ["retrieve", "grade_evidence", "answer"]
    assert planner.calls == 1
    assert status.calls == 0
    assert INJECTION not in result.model_dump_json()
    assert INJECTION not in caplog.text
    assert caplog.records == []


def test_expired_deadline_returns_safe_timeout_before_business_work() -> None:
    result, gateway, planner, status, store = _run_graph(
        budgets=AgentBudgets(),
        clock=DeadlineClock(started=0.0, deadline_seconds=25),
    )

    assert result.outcome is AgentOutcome.TIMED_OUT
    assert result.terminal_reason is TerminalReason.DEADLINE_EXCEEDED
    assert result.safe_error_code == "agent_deadline_exceeded"
    assert gateway.calls == []
    assert planner.calls == 0
    assert status.calls == 0
    assert len(store.states) == 1


def test_cancellation_releases_capacity_and_starts_no_replacement_work() -> None:
    async def scenario() -> None:
        class BlockingGraph:
            def __init__(self) -> None:
                self.started = asyncio.Event()
                self.replacement_calls = 0

            async def ainvoke(
                self,
                input: object,
                config: object | None = None,
                *,
                context: object | None = None,
            ) -> object:
                del input, config, context
                self.started.set()
                await asyncio.Event().wait()
                self.replacement_calls += 1
                raise AssertionError("cancelled graph must not continue")

        graph = BlockingGraph()
        gateway = _gateway()
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
            graph=graph,  # type: ignore[arg-type]
        )
        auth_context = _auth("reader", Role.READER)
        first = asyncio.create_task(
            controller.handle(
                StartAgentCommand(query="cancelled request"),
                auth_context,
                str(uuid4()),
            )
        )
        await graph.started.wait()
        with pytest.raises(AgentOverloadedError):
            await controller.handle(
                StartAgentCommand(query="replacement request"),
                auth_context,
                str(uuid4()),
            )
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        await asyncio.sleep(0)

        assert controller.active_runs == 0
        assert graph.replacement_calls == 0
        assert gateway.calls == []
        assert planner.calls == 0
        assert status.calls == 0
        assert store.states == []
        assert store.approvals == {}

    asyncio.run(scenario())


def test_step_budget_proves_acyclic_loop_safety_without_gateway_or_tool_work() -> None:
    budgets = AgentBudgets(maximum_graph_steps=1)
    result, gateway, planner, status, store = _run_graph(
        budgets=budgets,
        clock=DeadlineClock.start(budgets.agent_deadline_seconds),
    )

    assert result.outcome is AgentOutcome.BUDGET_EXCEEDED
    assert result.terminal_reason is TerminalReason.STEP_BUDGET_EXCEEDED
    assert result.safe_error_code == "agent_budget_exceeded"
    assert gateway.calls == []
    assert planner.calls == 0
    assert status.calls == 0
    assert len(store.states) == 1


def test_atomic_human_rejection_replays_safely_and_never_executes_tool() -> None:
    controller, gateway, planner, status, store = _controller(
        proposal=_write_proposal(),
        mock_write_enabled=False,
    )
    start = asyncio.run(
        controller.handle(
            StartAgentCommand(query="synthetic write proposal"),
            _auth("requester", Role.ADMIN),
            str(uuid4()),
        )
    )
    assert start.approval_id is not None
    pending = store.approvals[str(start.approval_id)]
    values = pending.model_dump(mode="python")
    values.update(
        status=ApprovalStatus.REJECTED,
        revision=pending.revision + 1,
        terminal_at=datetime.now(UTC),
    )
    rejected = ApprovalRecord.model_validate(values, strict=True)
    store.terminate_pending(
        rejected,
        expected_revision=pending.revision,
        maximum_bytes=AgentBudgets().maximum_serialized_state_bytes,
    )
    activity_before_decisions = (
        tuple(gateway.calls),
        planner.calls,
        len(store.states),
    )
    decision = _decision(start.approval_id)

    first = asyncio.run(
        controller.handle(
            decision,
            _auth("reviewer", Role.REVIEWER),
            str(uuid4()),
        )
    )
    replay = asyncio.run(
        controller.handle(
            decision,
            _auth("reviewer", Role.REVIEWER),
            str(uuid4()),
        )
    )

    for result in (first, replay):
        assert result.outcome is AgentOutcome.REJECTED
        assert result.terminal_reason is TerminalReason.APPROVAL_REJECTED
        assert result.result_reference_sha256 is None
    stored = store.approvals[str(start.approval_id)]
    assert stored.status is ApprovalStatus.REJECTED
    assert stored.result_reference_sha256 is None
    assert (
        tuple(gateway.calls),
        planner.calls,
        len(store.states),
    ) == activity_before_decisions
    assert status.calls == 0
    assert controller.active_runs == 0


def test_export_failure_preserves_result_and_redacts_all_approved_sentinels(
    valid_settings: Settings,
    caplog: pytest.LogCaptureFixture,
) -> None:
    clock = DeterministicClock()
    failing = FailingSpanExporter()
    composition = build_in_memory_telemetry(
        settings=valid_settings,
        monotonic=clock.monotonic,
        unix_time_ns=clock.unix_time_ns,
        span_exporter=failing,
    )
    raw_query = " ".join((INJECTION, SECRET, *SECURITY_SENTINELS))
    controller, gateway, planner, status, _ = _controller(
        telemetry=composition.runtime,
    )

    try:
        result = asyncio.run(
            controller.handle(
                StartAgentCommand(query=raw_query),
                _auth("reader", Role.READER),
                str(uuid4()),
            )
        )
        assert composition.runtime.force_flush() is True
        captured = "\n".join(
            (
                result.model_dump_json(),
                *(record.model_dump_json() for record in composition.log_sink.records()),
                repr(composition.metric_reader.get_metrics_data()),
                caplog.text,
            )
        )

        assert result.outcome is AgentOutcome.COMPLETED
        assert result.terminal_reason is TerminalReason.ANSWER_REFERENCE_READY
        assert gateway.calls == ["retrieve", "grade_evidence", "answer"]
        assert planner.calls == 1
        assert status.calls == 0
        assert failing.export_calls > 0
        assert "telemetry_export_failed" in captured
        for sentinel in (INJECTION, SECRET, *SECURITY_SENTINELS):
            assert sentinel not in captured
    finally:
        composition.runtime.shutdown()


def test_agent_telemetry_spans_metrics_and_logs_retain_no_approved_sentinel(
    telemetry_factory,
    caplog: pytest.LogCaptureFixture,
) -> None:  # type: ignore[no-untyped-def]
    composition = telemetry_factory()
    raw_query = " ".join((INJECTION, SECRET, *SECURITY_SENTINELS))
    controller, _, _, status, _ = _controller(telemetry=composition.runtime)

    result = asyncio.run(
        controller.handle(
            StartAgentCommand(query=raw_query),
            _auth("reader", Role.READER),
            str(uuid4()),
        )
    )
    assert composition.runtime.force_flush() is True
    assert isinstance(composition.span_exporter, BoundedInMemorySpanExporter)
    span_text: list[str] = []
    for span in composition.span_exporter.get_finished_spans():
        span_text.extend((span.name, repr(span.attributes), repr(span.status)))
        span_text.extend(
            f"{event.name}:{event.attributes!r}" for event in span.events
        )
    captured = "\n".join(
        (
            result.model_dump_json(),
            *span_text,
            *(record.model_dump_json() for record in composition.log_sink.records()),
            repr(composition.metric_reader.get_metrics_data()),
            caplog.text,
        )
    )

    assert result.outcome is AgentOutcome.COMPLETED
    assert result.terminal_reason is TerminalReason.ANSWER_REFERENCE_READY
    assert status.calls == 0
    for sentinel in (INJECTION, SECRET, *SECURITY_SENTINELS):
        assert sentinel not in captured
    assert caplog.records == []


def test_failure_scenario_leaves_no_store_file_task_or_thread_residue(
    tmp_path: Path,
) -> None:
    initial_threads = {thread.ident for thread in threading.enumerate()}
    controller, _, _, _, store = _controller()

    async def scenario() -> None:
        result = await controller.handle(
            StartAgentCommand(query=INJECTION),
            _auth("reader", Role.READER),
            str(uuid4()),
        )
        assert result.outcome is AgentOutcome.COMPLETED
        current = asyncio.current_task()
        assert {task for task in asyncio.all_tasks() if task is not current} == set()

    asyncio.run(scenario())
    store.states.clear()
    store.approvals.clear()

    assert controller.active_runs == 0
    assert store.states == []
    assert store.approvals == {}
    assert list(tmp_path.iterdir()) == []
    assert {thread.ident for thread in threading.enumerate()} == initial_threads
