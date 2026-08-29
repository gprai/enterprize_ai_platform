"""Exact routing tests for the bounded W4-002 LangGraph."""

from __future__ import annotations

import asyncio
from uuid import uuid4

from enterprise_ai_platform.agent.graph import (
    GRAPH_EDGES,
    GRAPH_NODES,
    AgentRunContext,
    build_agent_graph,
    graph_mermaid,
    initial_graph_state,
)
from enterprise_ai_platform.agent.models import (
    AgentBudgets,
    AgentOutcome,
    AnswerReference,
    EvidenceGrade,
    EvidencePacket,
    MockSetServiceModeArguments,
    ServiceStatusArguments,
    TerminalReason,
    ToolKind,
    ToolProposal,
)
from enterprise_ai_platform.agent.runtime import DeadlineClock
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


def _auth(*roles: Role) -> AuthContext:
    return AuthContext(
        subject_id="agent-requester",
        tenant_id="tenant-a",
        roles=frozenset(roles),
        clearance=Classification.INTERNAL,
    )


def _run(proposal: ToolProposal | None, auth: AuthContext) -> tuple[object, object]:
    gateway = FakeAgentGateway(
        evidence=EvidencePacket(references=("a" * 64,)),
        grade=EvidenceGrade(authorized=True, sufficient=True),
        answer=AnswerReference(result_reference_sha256="b" * 64, total_tokens=10),
    )
    store = InMemoryAgentStore()
    request_id = uuid4()
    run_id = uuid4()
    context = AgentRunContext(
        query="bounded request",
        auth_context=auth,
        request_id=request_id,
        run_id=run_id,
        gateway=gateway,
        planner=FakeAgentPlanner(proposal),
        registry=ToolRegistry(FakeLocalStatusProvider(), mock_write_enabled=True),
        store=store,
        budgets=AgentBudgets(),
        clock=DeadlineClock.start(25),
        approval_ttl_seconds=600,
    )
    result = asyncio.run(
        build_agent_graph().ainvoke(
            initial_graph_state(
                request_id=request_id,
                run_id=run_id,
                auth_context=auth,
            ),
            context=context,
        )
    )
    return result, store


def test_graph_has_exact_nodes_edges_and_generated_mermaid() -> None:
    assert GRAPH_NODES == (
        "validate_input",
        "authorize",
        "retrieve",
        "grade_evidence",
        "answer",
        "propose_tool",
        "await_human_approval",
        "execute_tool",
        "safe_terminal",
    )
    assert len(GRAPH_EDGES) == 10
    mermaid = graph_mermaid()
    for node in GRAPH_NODES:
        assert node in mermaid
    for source, destination in GRAPH_EDGES[1:-1]:
        assert mermaid.index(source) < len(mermaid)
        assert destination in mermaid


def test_read_tool_path_reaches_one_safe_terminal() -> None:
    proposal = ToolProposal(
        name="get_service_status",
        kind=ToolKind.READ,
        arguments=ServiceStatusArguments(component="query_wiring"),
    )
    raw, store = _run(proposal, _auth(Role.READER))
    result = raw["control"]

    assert result.outcome is AgentOutcome.COMPLETED
    assert result.terminal_reason is TerminalReason.READ_TOOL_COMPLETED
    assert result.step_count == 8
    assert result.tool_call_count == 1
    assert len(store.states) == 1


def test_mock_write_stops_before_execution_for_durable_approval() -> None:
    proposal = ToolProposal(
        name="mock_set_service_mode",
        kind=ToolKind.MOCK_WRITE,
        arguments=MockSetServiceModeArguments(mode="maintenance"),
    )
    raw, store = _run(proposal, _auth(Role.ADMIN))
    result = raw["control"]

    assert result.outcome is AgentOutcome.APPROVAL_REQUIRED
    assert result.terminal_reason is TerminalReason.APPROVAL_REQUIRED
    assert result.tool_call_count == 0
    assert len(store.approvals) == 1


def test_no_cycle_is_present_in_the_exact_edge_set() -> None:
    ordered = {node: index for index, node in enumerate(GRAPH_NODES)}
    for source, destination in GRAPH_EDGES[1:-1]:
        assert ordered[str(source)] < ordered[str(destination)]
