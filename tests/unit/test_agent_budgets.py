"""Independent W4-002 budget, deadline, and capacity contracts."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from enterprise_ai_platform.agent.controller import BoundedAgentController
from enterprise_ai_platform.agent.errors import AgentOverloadedError
from enterprise_ai_platform.agent.graph import (
    AgentRunContext,
    build_agent_graph,
    initial_graph_state,
)
from enterprise_ai_platform.agent.models import (
    AgentBudgets,
    AgentNode,
    AgentOutcome,
    AgentState,
    AnswerReference,
    EvidenceGrade,
    EvidencePacket,
    ServiceStatusArguments,
    StartAgentCommand,
    TerminalReason,
    ToolKind,
    ToolProposal,
)
from enterprise_ai_platform.agent.runtime import (
    AgentCapacityLimiter,
    DeadlineClock,
    apply_budget_terminal,
)
from enterprise_ai_platform.agent.tools import ToolRegistry
from enterprise_ai_platform.retrieval.models import (
    AuthContext,
    Classification,
    Role,
)
from tests.fakes.agent import (
    FakeAgentGateway,
    FakeAgentPlanner,
    FakeLocalStatusProvider,
    InMemoryAgentStore,
)


def _state(**updates: object) -> AgentState:
    values: dict[str, object] = {
        "request_id": uuid4(),
        "run_id": uuid4(),
        "tenant_reference_sha256": "a" * 64,
        "subject_reference_sha256": "b" * 64,
        "authorization_reference_sha256": "c" * 64,
        "current_node": AgentNode.ANSWER,
    }
    values.update(updates)
    return AgentState.model_validate(values, strict=True)


def _run_graph_with_bounds(
    budgets: AgentBudgets,
    *,
    control_updates: dict[str, object] | None = None,
    total_tokens: int = 1,
    proposal: ToolProposal | None = None,
    clock: DeadlineClock | None = None,
) -> tuple[
    AgentState,
    FakeAgentGateway,
    FakeAgentPlanner,
    FakeLocalStatusProvider,
    InMemoryAgentStore,
]:
    auth = AuthContext(
        subject_id="reader",
        tenant_id="tenant-a",
        roles=frozenset({Role.READER}),
        clearance=Classification.INTERNAL,
    )
    gateway = FakeAgentGateway(
        evidence=EvidencePacket(references=("a" * 64,)),
        grade=EvidenceGrade(authorized=True, sufficient=True),
        answer=AnswerReference(
            result_reference_sha256="b" * 64,
            total_tokens=total_tokens,
        ),
    )
    planner = FakeAgentPlanner(proposal)
    status = FakeLocalStatusProvider()
    store = InMemoryAgentStore()
    request_id = uuid4()
    run_id = uuid4()
    initial = initial_graph_state(
        request_id=request_id,
        run_id=run_id,
        auth_context=auth,
    )
    if control_updates:
        values = initial["control"].model_dump(mode="python")
        values.update(control_updates)
        initial["control"] = AgentState.model_validate(values, strict=True)
    context = AgentRunContext(
        query="bounded request",
        auth_context=auth,
        request_id=request_id,
        run_id=run_id,
        gateway=gateway,
        planner=planner,
        registry=ToolRegistry(status, mock_write_enabled=False),
        store=store,
        budgets=budgets,
        clock=clock or DeadlineClock.start(budgets.agent_deadline_seconds),
        approval_ttl_seconds=600,
    )
    result = asyncio.run(build_agent_graph().ainvoke(initial, context=context))
    return result["control"], gateway, planner, status, store


def test_token_budget_stops_with_no_retry() -> None:
    result = apply_budget_terminal(
        _state(total_tokens=11),
        AgentBudgets(maximum_total_tokens=10),
    )
    assert result.outcome is AgentOutcome.BUDGET_EXCEEDED
    assert result.terminal_reason is TerminalReason.TOKEN_BUDGET_EXCEEDED
    assert result.retry_count == 0


def test_serialized_state_budget_stops_safely() -> None:
    result = apply_budget_terminal(
        _state(),
        AgentBudgets(maximum_serialized_state_bytes=10),
        serialized_bytes=11,
    )
    assert result.terminal_reason is TerminalReason.STATE_BUDGET_EXCEEDED


def test_step_budget_stops_before_gateway_activity() -> None:
    result, gateway, planner, status, store = _run_graph_with_bounds(
        AgentBudgets(maximum_graph_steps=1)
    )
    assert result.terminal_reason is TerminalReason.STEP_BUDGET_EXCEEDED
    assert gateway.calls == []
    assert planner.calls == 0
    assert status.calls == 0
    assert len(store.states) == 1


def test_provider_budget_stops_before_a_repeated_provider_attempt() -> None:
    result, gateway, planner, status, _ = _run_graph_with_bounds(
        AgentBudgets(),
        control_updates={"provider_attempt_count": 1},
    )
    assert result.terminal_reason is TerminalReason.PROVIDER_BUDGET_EXCEEDED
    assert gateway.calls == ["retrieve", "grade_evidence"]
    assert planner.calls == 0
    assert status.calls == 0


def test_tool_budget_stops_before_a_repeated_tool_call() -> None:
    proposal = ToolProposal(
        name="get_service_status",
        kind=ToolKind.READ,
        arguments=ServiceStatusArguments(component="query_wiring"),
    )
    result, gateway, planner, status, _ = _run_graph_with_bounds(
        AgentBudgets(),
        control_updates={"tool_call_count": 1},
        proposal=proposal,
    )
    assert result.terminal_reason is TerminalReason.TOOL_BUDGET_EXCEEDED
    assert gateway.calls == ["retrieve", "grade_evidence", "answer"]
    assert planner.calls == 1
    assert status.calls == 0


def test_token_budget_stops_before_planner_or_tool_activity() -> None:
    result, gateway, planner, status, _ = _run_graph_with_bounds(
        AgentBudgets(maximum_total_tokens=10),
        total_tokens=11,
    )
    assert result.terminal_reason is TerminalReason.TOKEN_BUDGET_EXCEEDED
    assert gateway.calls == ["retrieve", "grade_evidence", "answer"]
    assert planner.calls == 0
    assert status.calls == 0


def test_state_budget_returns_safe_terminal_without_persisting_oversize_state() -> None:
    result, _, planner, status, store = _run_graph_with_bounds(
        AgentBudgets(maximum_serialized_state_bytes=10)
    )
    assert result.terminal_reason is TerminalReason.STATE_BUDGET_EXCEEDED
    assert planner.calls == 1
    assert status.calls == 0
    assert store.states == []


def test_expired_deadline_starts_no_gateway_planner_or_tool_work() -> None:
    result, gateway, planner, status, _ = _run_graph_with_bounds(
        AgentBudgets(),
        clock=DeadlineClock(started=0.0, deadline_seconds=25),
    )
    assert result.terminal_reason is TerminalReason.DEADLINE_EXCEEDED
    assert gateway.calls == []
    assert planner.calls == 0
    assert status.calls == 0


def test_exact_default_budgets_match_owner_decision() -> None:
    budgets = AgentBudgets()
    assert budgets.model_dump(mode="json") == {
        "maximum_graph_steps": 8,
        "maximum_tool_calls": 1,
        "maximum_provider_attempts": 1,
        "maximum_total_tokens": 4096,
        "graph_retries": 0,
        "agent_deadline_seconds": 25,
        "maximum_serialized_state_bytes": 16384,
        "maximum_concurrent_agent_runs": 1,
        "agent_queue_capacity": 0,
    }


def test_capacity_is_atomic_non_waiting_and_released() -> None:
    limiter = AgentCapacityLimiter()
    assert limiter.try_acquire() is True
    assert limiter.try_acquire() is False
    assert limiter.active == 1
    limiter.release()
    assert limiter.active == 0
    assert limiter.try_acquire() is True
    limiter.release()


def test_controller_cancellation_releases_capacity_without_replacement_work() -> None:
    class BlockingGraph:
        def __init__(self) -> None:
            self.started = asyncio.Event()

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
            raise AssertionError("cancelled graph must not continue")

    async def scenario() -> None:
        graph = BlockingGraph()
        controller = BoundedAgentController(
            gateway=FakeAgentGateway(
                evidence=EvidencePacket(references=("a" * 64,)),
                grade=EvidenceGrade(authorized=True, sufficient=True),
                answer=AnswerReference(
                    result_reference_sha256="b" * 64,
                    total_tokens=1,
                ),
            ),
            planner=FakeAgentPlanner(None),
            status_provider=FakeLocalStatusProvider(),
            store=InMemoryAgentStore(),
            budgets=AgentBudgets(),
            mock_write_enabled=False,
            graph=graph,  # type: ignore[arg-type]
        )
        auth = AuthContext(
            subject_id="reader",
            tenant_id="tenant-a",
            roles=frozenset({Role.READER}),
            clearance=Classification.INTERNAL,
        )
        first = asyncio.create_task(
            controller.handle(StartAgentCommand(query="first"), auth, str(uuid4()))
        )
        await graph.started.wait()
        with pytest.raises(AgentOverloadedError):
            await controller.handle(StartAgentCommand(query="second"), auth, str(uuid4()))
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert controller.active_runs == 0

    asyncio.run(scenario())
