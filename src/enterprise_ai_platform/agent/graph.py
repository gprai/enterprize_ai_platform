"""Explicit acyclic LangGraph workflow for the bounded W4-002 agent."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol, TypedDict, cast
from uuid import UUID, uuid4

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from enterprise_ai_platform.retrieval.models import AuthContext

from .authorization import authorization_reference, require_tool_authorized
from .contracts import AgentEvidenceGateway, AgentPlanner, AgentStateStore
from .models import (
    AgentBudgets,
    AgentNode,
    AgentOutcome,
    AgentState,
    AnswerReference,
    ApprovalRecord,
    AuditDecision,
    EvidenceGrade,
    EvidencePacket,
    TerminalReason,
    ToolKind,
    ToolProposal,
)
from .runtime import DeadlineClock, apply_budget_terminal
from .serialization import canonical_bytes, hash_identifier
from .tools import ToolRegistry


class AgentGraphState(TypedDict):
    control: AgentState
    evidence: EvidencePacket | None
    grade: EvidenceGrade | None
    answer: AnswerReference | None
    proposal: ToolProposal | None


@dataclass(frozen=True, slots=True)
class AgentRunContext:
    query: str
    auth_context: AuthContext
    request_id: UUID
    run_id: UUID
    gateway: AgentEvidenceGateway
    planner: AgentPlanner
    registry: ToolRegistry
    store: AgentStateStore
    budgets: AgentBudgets
    clock: DeadlineClock
    approval_ttl_seconds: int


class DrawableGraph(Protocol):
    def draw_mermaid(self) -> str: ...


class CompiledAgentGraph(Protocol):
    async def ainvoke(
        self,
        input: AgentGraphState,
        config: object | None = None,
        *,
        context: AgentRunContext | None = None,
    ) -> AgentGraphState: ...

    def get_graph(self) -> DrawableGraph: ...


GRAPH_NODES = tuple(node.value for node in AgentNode)
GRAPH_EDGES = (
    (START, AgentNode.VALIDATE_INPUT.value),
    (AgentNode.VALIDATE_INPUT.value, AgentNode.AUTHORIZE.value),
    (AgentNode.AUTHORIZE.value, AgentNode.RETRIEVE.value),
    (AgentNode.RETRIEVE.value, AgentNode.GRADE_EVIDENCE.value),
    (AgentNode.GRADE_EVIDENCE.value, AgentNode.ANSWER.value),
    (AgentNode.ANSWER.value, AgentNode.PROPOSE_TOOL.value),
    (AgentNode.PROPOSE_TOOL.value, AgentNode.AWAIT_HUMAN_APPROVAL.value),
    (AgentNode.AWAIT_HUMAN_APPROVAL.value, AgentNode.EXECUTE_TOOL.value),
    (AgentNode.EXECUTE_TOOL.value, AgentNode.SAFE_TERMINAL.value),
    (AgentNode.SAFE_TERMINAL.value, END),
)


def _updated(control: AgentState, **updates: object) -> AgentState:
    values = control.model_dump(mode="python")
    values.update(updates)
    return AgentState.model_validate(values, strict=True)


def _enter(
    control: AgentState,
    node: AgentNode,
    context: AgentRunContext,
) -> AgentState:
    if control.outcome is not None:
        return control
    if context.clock.expired():
        return _updated(
            control,
            current_node=node,
            outcome=AgentOutcome.TIMED_OUT,
            terminal_reason=TerminalReason.DEADLINE_EXCEEDED,
            safe_error_code="agent_deadline_exceeded",
            elapsed_milliseconds=context.budgets.agent_deadline_seconds * 1000,
        )
    if control.step_count >= context.budgets.maximum_graph_steps:
        return _updated(
            control,
            current_node=node,
            outcome=AgentOutcome.BUDGET_EXCEEDED,
            terminal_reason=TerminalReason.STEP_BUDGET_EXCEEDED,
            safe_error_code="agent_budget_exceeded",
            elapsed_milliseconds=context.clock.elapsed_milliseconds(),
        )
    audit = control.audit_decisions + (
        AuditDecision(
            sequence=len(control.audit_decisions) + 1,
            node=node,
            decision="entered",
        ),
    )
    return _updated(
        control,
        current_node=node,
        step_count=control.step_count + 1,
        elapsed_milliseconds=context.clock.elapsed_milliseconds(),
        audit_decisions=audit,
    )


def _terminal(control: AgentState) -> bool:
    return control.outcome is not None


async def validate_input(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(state["control"], AgentNode.VALIDATE_INPUT, runtime.context)
    if not _terminal(control) and (
        not runtime.context.query or len(runtime.context.query) > 10_000
    ):
        control = _updated(
            control,
            outcome=AgentOutcome.SAFE_TERMINAL,
            terminal_reason=TerminalReason.SAFE_FAILURE,
            safe_error_code="api_request_invalid",
        )
    return {"control": control}


async def authorize(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(state["control"], AgentNode.AUTHORIZE, runtime.context)
    if not _terminal(control) and (
        authorization_reference(runtime.context.auth_context)
        != control.authorization_reference_sha256
    ):
        control = _updated(
            control,
            outcome=AgentOutcome.DENIED,
            terminal_reason=TerminalReason.AUTHORIZATION_DENIED,
            safe_error_code="authorization_denied",
        )
    return {"control": control}


async def retrieve(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(state["control"], AgentNode.RETRIEVE, runtime.context)
    if _terminal(control):
        return {"control": control}
    evidence = await runtime.context.gateway.retrieve(
        runtime.context.auth_context,
        runtime.context.query,
    )
    return {
        "control": _updated(
            control,
            evidence_reference_sha256=evidence.references,
        ),
        "evidence": evidence,
    }


async def grade_evidence(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(state["control"], AgentNode.GRADE_EVIDENCE, runtime.context)
    evidence = state["evidence"]
    if _terminal(control) or evidence is None:
        return {"control": control}
    grade = await runtime.context.gateway.grade_evidence(
        runtime.context.auth_context,
        evidence,
    )
    if not grade.authorized:
        control = _updated(
            control,
            outcome=AgentOutcome.DENIED,
            terminal_reason=TerminalReason.EVIDENCE_NOT_AUTHORIZED,
            safe_error_code="authorization_denied",
        )
    elif not grade.sufficient:
        control = _updated(
            control,
            outcome=AgentOutcome.SAFE_TERMINAL,
            terminal_reason=TerminalReason.EVIDENCE_INSUFFICIENT,
        )
    return {"control": control, "grade": grade}


async def answer(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(state["control"], AgentNode.ANSWER, runtime.context)
    evidence = state["evidence"]
    grade = state["grade"]
    if _terminal(control) or evidence is None or grade is None:
        return {"control": control}
    if (
        control.provider_attempt_count
        >= runtime.context.budgets.maximum_provider_attempts
    ):
        return {
            "control": _updated(
                control,
                outcome=AgentOutcome.BUDGET_EXCEEDED,
                terminal_reason=TerminalReason.PROVIDER_BUDGET_EXCEEDED,
                safe_error_code="agent_budget_exceeded",
            )
        }
    answer_reference = await runtime.context.gateway.answer(
        runtime.context.auth_context,
        runtime.context.query,
        evidence,
    )
    control = _updated(
        control,
        provider_attempt_count=control.provider_attempt_count + 1,
        total_tokens=answer_reference.total_tokens,
        result_reference_sha256=answer_reference.result_reference_sha256,
    )
    control = apply_budget_terminal(control, runtime.context.budgets)
    return {"control": control, "answer": answer_reference}


async def propose_tool(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(state["control"], AgentNode.PROPOSE_TOOL, runtime.context)
    answer_reference = state["answer"]
    if _terminal(control) or answer_reference is None:
        return {"control": control}
    proposal = await runtime.context.planner.propose(
        runtime.context.auth_context,
        runtime.context.query,
        answer_reference,
    )
    if proposal is None:
        return {
            "control": _updated(
                control,
                outcome=AgentOutcome.COMPLETED,
                terminal_reason=TerminalReason.ANSWER_REFERENCE_READY,
            )
        }
    runtime.context.registry.validate(proposal)
    require_tool_authorized(runtime.context.auth_context, proposal.kind)
    return {
        "control": _updated(
            control,
            tool_name=proposal.name,
            tool_version=proposal.version,
            arguments_sha256=runtime.context.registry.arguments_fingerprint(proposal),
        ),
        "proposal": proposal,
    }


async def await_human_approval(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(
        state["control"],
        AgentNode.AWAIT_HUMAN_APPROVAL,
        runtime.context,
    )
    proposal = state["proposal"]
    if _terminal(control) or proposal is None or proposal.kind is ToolKind.READ:
        return {"control": control}
    now = datetime.now(UTC)
    approval = ApprovalRecord(
        approval_id=uuid4(),
        request_id=runtime.context.request_id,
        run_id=runtime.context.run_id,
        tenant_reference_sha256=control.tenant_reference_sha256,
        requester_reference_sha256=control.subject_reference_sha256,
        authorization_reference_sha256=control.authorization_reference_sha256,
        tool_name="mock_set_service_mode",
        arguments_sha256=runtime.context.registry.arguments_fingerprint(proposal),
        created_at=now,
        expires_at=now + timedelta(seconds=runtime.context.approval_ttl_seconds),
    )
    runtime.context.store.create_approval(
        approval,
        maximum_bytes=runtime.context.budgets.maximum_serialized_state_bytes,
    )
    return {
        "control": _updated(
            control,
            outcome=AgentOutcome.APPROVAL_REQUIRED,
            terminal_reason=TerminalReason.APPROVAL_REQUIRED,
            approval_id=approval.approval_id,
            approval_status=approval.status,
            approval_expires_at=approval.expires_at,
        )
    }


async def execute_tool(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _enter(state["control"], AgentNode.EXECUTE_TOOL, runtime.context)
    proposal = state["proposal"]
    if _terminal(control) or proposal is None:
        return {"control": control}
    if proposal.kind is not ToolKind.READ:
        return {"control": control}
    if control.tool_call_count >= runtime.context.budgets.maximum_tool_calls:
        return {
            "control": _updated(
                control,
                outcome=AgentOutcome.BUDGET_EXCEEDED,
                terminal_reason=TerminalReason.TOOL_BUDGET_EXCEEDED,
                safe_error_code="agent_budget_exceeded",
            )
        }
    result_reference = await runtime.context.registry.execute_read(proposal)
    return {
        "control": _updated(
            control,
            tool_call_count=control.tool_call_count + 1,
            result_reference_sha256=result_reference,
            outcome=AgentOutcome.COMPLETED,
            terminal_reason=TerminalReason.READ_TOOL_COMPLETED,
        )
    }


async def safe_terminal(
    state: AgentGraphState,
    runtime: Runtime[AgentRunContext],
) -> dict[str, object]:
    control = _updated(
        state["control"],
        current_node=AgentNode.SAFE_TERMINAL,
        elapsed_milliseconds=min(
            runtime.context.clock.elapsed_milliseconds(),
            runtime.context.budgets.agent_deadline_seconds * 1000,
        ),
    )
    if not _terminal(control):
        control = _updated(
            control,
            outcome=AgentOutcome.SAFE_TERMINAL,
            terminal_reason=TerminalReason.SAFE_FAILURE,
            safe_error_code="internal_error",
        )
    serialized = canonical_bytes(control)
    control = apply_budget_terminal(
        control,
        runtime.context.budgets,
        serialized_bytes=len(serialized),
    )
    if control.terminal_reason is not TerminalReason.STATE_BUDGET_EXCEEDED:
        runtime.context.store.save_state(
            control,
            maximum_bytes=runtime.context.budgets.maximum_serialized_state_bytes,
        )
    return {"control": control}


def build_agent_graph() -> CompiledAgentGraph:
    """Compile the exact nine-node graph without retry policy or checkpointer."""

    graph = StateGraph(AgentGraphState, context_schema=AgentRunContext)
    graph.add_node(AgentNode.VALIDATE_INPUT.value, validate_input)
    graph.add_node(AgentNode.AUTHORIZE.value, authorize)
    graph.add_node(AgentNode.RETRIEVE.value, retrieve)
    graph.add_node(AgentNode.GRADE_EVIDENCE.value, grade_evidence)
    graph.add_node(AgentNode.ANSWER.value, answer)
    graph.add_node(AgentNode.PROPOSE_TOOL.value, propose_tool)
    graph.add_node(AgentNode.AWAIT_HUMAN_APPROVAL.value, await_human_approval)
    graph.add_node(AgentNode.EXECUTE_TOOL.value, execute_tool)
    graph.add_node(AgentNode.SAFE_TERMINAL.value, safe_terminal)
    for source, destination in GRAPH_EDGES:
        graph.add_edge(source, destination)
    return cast(CompiledAgentGraph, graph.compile())


def graph_mermaid() -> str:
    """Generate Mermaid from the same compiled graph used at runtime."""

    return build_agent_graph().get_graph().draw_mermaid()


def initial_graph_state(
    *,
    request_id: UUID,
    run_id: UUID,
    auth_context: AuthContext,
) -> AgentGraphState:
    return {
        "control": AgentState(
            request_id=request_id,
            run_id=run_id,
            tenant_reference_sha256=hash_identifier(auth_context.tenant_id),
            subject_reference_sha256=hash_identifier(auth_context.subject_id),
            authorization_reference_sha256=authorization_reference(auth_context),
            current_node=AgentNode.VALIDATE_INPUT,
        ),
        "evidence": None,
        "grade": None,
        "answer": None,
        "proposal": None,
    }
