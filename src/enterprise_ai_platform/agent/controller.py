"""Bounded orchestration and one-time approval consumption for W4-002."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from uuid import UUID, uuid4

from enterprise_ai_platform.retrieval.models import AuthContext
from enterprise_ai_platform.telemetry.models import (
    SafeTelemetryAttributes,
    TelemetryEventName,
    TelemetryOperation,
    TelemetryOutcome,
    TelemetryStage,
)
from enterprise_ai_platform.telemetry.runtime import (
    NullTelemetryRuntime,
    TelemetryRuntime,
)

from .authorization import (
    authorization_reference,
    require_approver_authorized,
    require_decision_authorized,
    require_start_authorized,
)
from .contracts import (
    AgentEvidenceGateway,
    AgentPlanner,
    AgentStateStore,
    LocalStatusProvider,
)
from .errors import (
    AgentApprovalConflictError,
    AgentAuthorizationError,
    AgentDeadlineError,
    AgentOverloadedError,
)
from .graph import (
    AgentRunContext,
    CompiledAgentGraph,
    build_agent_graph,
    initial_graph_state,
)
from .models import (
    AgentBudgets,
    AgentCommand,
    AgentNode,
    AgentOutcome,
    AgentResult,
    AgentState,
    ApprovalRecord,
    ApprovalStatus,
    DecideAgentCommand,
    TerminalReason,
    ToolKind,
    ToolProposal,
)
from .runtime import AgentCapacityLimiter, DeadlineClock
from .serialization import hash_identifier
from .tools import ToolRegistry


def _updated_approval(record: ApprovalRecord, **updates: object) -> ApprovalRecord:
    values = record.model_dump(mode="python")
    values.update(updates)
    return ApprovalRecord.model_validate(values, strict=True)


class BoundedAgentController:
    """Run one explicit graph or consume one approval under exact bounds."""

    def __init__(
        self,
        *,
        gateway: AgentEvidenceGateway,
        planner: AgentPlanner,
        status_provider: LocalStatusProvider,
        store: AgentStateStore,
        budgets: AgentBudgets,
        mock_write_enabled: bool,
        approval_ttl_seconds: int = 600,
        graph: CompiledAgentGraph | None = None,
        telemetry: TelemetryRuntime | None = None,
    ) -> None:
        if approval_ttl_seconds != 600:
            raise ValueError("W4-002 approval TTL must be ten minutes")
        if budgets.graph_retries != 0 or budgets.agent_queue_capacity != 0:
            raise ValueError("W4-002 retries and queue capacity must remain zero")
        self._gateway = gateway
        self._planner = planner
        self._store = store
        self._budgets = budgets
        self._approval_ttl_seconds = approval_ttl_seconds
        self._graph = graph if graph is not None else build_agent_graph()
        self._registry = ToolRegistry(
            status_provider,
            mock_write_enabled=mock_write_enabled,
        )
        self._limiter = AgentCapacityLimiter(budgets.maximum_concurrent_agent_runs)
        self._telemetry = telemetry or NullTelemetryRuntime()

    @property
    def active_runs(self) -> int:
        return self._limiter.active

    async def handle(
        self,
        transport: AgentCommand,
        auth_context: AuthContext,
        request_id: str,
    ) -> AgentResult:
        if not self._limiter.try_acquire():
            raise AgentOverloadedError
        try:
            with self._telemetry.start_scope(
                TelemetryStage.AGENT,
                TelemetryOperation.HANDLE,
                graph_version="w4-002.graph.v1",
            ) as agent_scope:
                try:
                    async with asyncio.timeout(self._budgets.agent_deadline_seconds):
                        self._authorize_command(transport, auth_context)
                        if isinstance(transport, DecideAgentCommand):
                            result = self._decide(
                                transport,
                                auth_context,
                                UUID(request_id),
                            )
                        else:
                            result = await self._start(
                                transport.query,
                                auth_context,
                                UUID(request_id),
                            )
                        agent_scope.finish(
                            _telemetry_outcome(result.outcome),
                            terminal_reason=result.terminal_reason.value,
                            safe_error_code=result.safe_error_code,
                        )
                        return result
                except AgentAuthorizationError:
                    agent_scope.finish(
                        TelemetryOutcome.DENIED,
                        terminal_reason=TerminalReason.AUTHORIZATION_DENIED.value,
                        safe_error_code="authorization_denied",
                    )
                    raise
                except (TimeoutError, AgentDeadlineError):
                    agent_scope.finish(
                        TelemetryOutcome.TIMEOUT,
                        terminal_reason=TerminalReason.DEADLINE_EXCEEDED.value,
                        safe_error_code="agent_deadline_exceeded",
                    )
                    raise AgentDeadlineError from None
        finally:
            self._limiter.release()

    def _authorize_command(
        self,
        transport: AgentCommand,
        auth_context: AuthContext,
    ) -> None:
        with self._telemetry.start_scope(
            TelemetryStage.AUTHORIZATION,
            TelemetryOperation.AUTHORIZE,
        ) as authorization_scope:
            try:
                if isinstance(transport, DecideAgentCommand):
                    require_decision_authorized(auth_context)
                else:
                    require_start_authorized(auth_context)
            except AgentAuthorizationError:
                authorization_scope.finish(
                    TelemetryOutcome.DENIED,
                    terminal_reason=TerminalReason.AUTHORIZATION_DENIED.value,
                    safe_error_code="authorization_denied",
                )
                self._telemetry.emit_event(
                    TelemetryEventName.SECURITY_DECISION,
                    SafeTelemetryAttributes(
                        stage=TelemetryStage.AUTHORIZATION,
                        operation=TelemetryOperation.AUTHORIZE,
                        outcome=TelemetryOutcome.DENIED,
                        terminal_reason=(TerminalReason.AUTHORIZATION_DENIED.value),
                        safe_error_code="authorization_denied",
                    ),
                )
                raise
            authorization_scope.finish(TelemetryOutcome.SUCCESS)
            self._telemetry.emit_event(
                TelemetryEventName.SECURITY_DECISION,
                SafeTelemetryAttributes(
                    stage=TelemetryStage.AUTHORIZATION,
                    operation=TelemetryOperation.AUTHORIZE,
                    outcome=TelemetryOutcome.SUCCESS,
                ),
            )

    async def _start(
        self,
        query: str,
        auth_context: AuthContext,
        request_id: UUID,
    ) -> AgentResult:
        run_id = uuid4()
        clock = DeadlineClock.start(self._budgets.agent_deadline_seconds)
        context = AgentRunContext(
            query=query,
            auth_context=auth_context,
            request_id=request_id,
            run_id=run_id,
            gateway=self._gateway,
            planner=self._planner,
            registry=self._registry,
            store=self._store,
            budgets=self._budgets,
            clock=clock,
            approval_ttl_seconds=self._approval_ttl_seconds,
            telemetry=self._telemetry,
        )
        final = await self._graph.ainvoke(
            initial_graph_state(
                request_id=request_id,
                run_id=run_id,
                auth_context=auth_context,
            ),
            context=context,
        )
        state = final["control"]
        if state.terminal_reason is TerminalReason.DEADLINE_EXCEEDED:
            raise AgentDeadlineError
        if state.terminal_reason in {
            TerminalReason.AUTHORIZATION_DENIED,
            TerminalReason.EVIDENCE_NOT_AUTHORIZED,
        }:
            raise AgentAuthorizationError
        if state.outcome is None or state.terminal_reason is None:
            raise AgentApprovalConflictError
        return AgentResult(
            request_id=request_id,
            run_id=run_id,
            outcome=state.outcome,
            terminal_reason=state.terminal_reason,
            approval_id=state.approval_id,
            result_reference_sha256=state.result_reference_sha256,
            safe_error_code=state.safe_error_code,
        )

    def _decide(
        self,
        command: DecideAgentCommand,
        auth_context: AuthContext,
        request_id: UUID,
    ) -> AgentResult:
        with self._telemetry.start_scope(
            TelemetryStage.APPROVAL,
            TelemetryOperation.EVALUATE,
        ) as approval_scope:
            result = self._decide_unobserved(command, auth_context, request_id)
            approval_scope.finish(
                _telemetry_outcome(result.outcome),
                terminal_reason=result.terminal_reason.value,
                safe_error_code=result.safe_error_code,
            )
            self._telemetry.emit_event(
                TelemetryEventName.APPROVAL_DECISION,
                SafeTelemetryAttributes(
                    stage=TelemetryStage.APPROVAL,
                    operation=TelemetryOperation.EVALUATE,
                    outcome=_telemetry_outcome(result.outcome),
                    terminal_reason=result.terminal_reason.value,
                    safe_error_code=result.safe_error_code,
                ),
            )
            return result

    def _decide_unobserved(
        self,
        command: DecideAgentCommand,
        auth_context: AuthContext,
        request_id: UUID,
    ) -> AgentResult:
        maximum_bytes = self._budgets.maximum_serialized_state_bytes
        current = self._store.get_approval(
            str(command.approval_id),
            maximum_bytes=maximum_bytes,
        )
        if current is None:
            raise AgentApprovalConflictError
        if current.request_id == request_id:
            raise AgentApprovalConflictError
        require_approver_authorized(
            auth_context,
            tenant_reference_sha256=current.tenant_reference_sha256,
            requester_reference_sha256=current.requester_reference_sha256,
        )
        terminal_approval = {
            ApprovalStatus.REJECTED: (
                AgentOutcome.REJECTED,
                TerminalReason.APPROVAL_REJECTED,
            ),
            ApprovalStatus.EXPIRED: (
                AgentOutcome.EXPIRED,
                TerminalReason.APPROVAL_EXPIRED,
            ),
            ApprovalStatus.CANCELLED: (
                AgentOutcome.CANCELLED,
                TerminalReason.APPROVAL_CANCELLED,
            ),
        }.get(current.status)
        if terminal_approval is not None:
            outcome, reason = terminal_approval
            return AgentResult(
                request_id=request_id,
                run_id=current.run_id,
                approval_id=current.approval_id,
                outcome=outcome,
                terminal_reason=reason,
            )
        if current.status is not ApprovalStatus.PENDING:
            raise AgentApprovalConflictError
        if datetime.now(UTC) >= current.expires_at:
            now = datetime.now(UTC)
            expired = _updated_approval(
                current,
                status=ApprovalStatus.EXPIRED,
                revision=current.revision + 1,
                terminal_at=now,
                safe_error_code="agent_approval_expired",
            )
            self._store.terminate_pending(
                expired,
                expected_revision=current.revision,
                maximum_bytes=maximum_bytes,
            )
            return AgentResult(
                request_id=request_id,
                run_id=current.run_id,
                approval_id=current.approval_id,
                outcome=AgentOutcome.EXPIRED,
                terminal_reason=TerminalReason.APPROVAL_EXPIRED,
            )
        proposal = ToolProposal(
            name=command.tool_name,
            version=command.tool_version,
            kind=ToolKind.MOCK_WRITE,
            arguments=command.arguments,
        )
        if (
            current.tool_name != command.tool_name
            or current.tool_version != command.tool_version
            or current.arguments_sha256 != self._registry.arguments_fingerprint(proposal)
        ):
            raise AgentApprovalConflictError
        now = datetime.now(UTC)
        approved = _updated_approval(
            current,
            status=ApprovalStatus.APPROVED,
            revision=current.revision + 1,
            approver_reference_sha256=hash_identifier(auth_context.subject_id),
            approver_role="reviewer",
            idempotency_key_sha256=hash_identifier(str(command.idempotency_key)),
            decision=command.decision,
            decided_at=now,
        )
        with self._telemetry.start_scope(
            TelemetryStage.APPROVAL,
            TelemetryOperation.PERSIST,
        ) as persist_scope:
            approved = self._store.approve(
                approved,
                expected_revision=current.revision,
                maximum_bytes=maximum_bytes,
            )
            executing = self._store.claim(
                str(approved.approval_id),
                expected_revision=approved.revision,
                maximum_bytes=maximum_bytes,
            )
            persist_scope.finish(TelemetryOutcome.SUCCESS)
        try:
            with self._telemetry.start_scope(
                TelemetryStage.TOOL,
                TelemetryOperation.EXECUTE_TOOL,
                tool_name=proposal.name,
                tool_version=proposal.version,
            ) as tool_scope:
                result_reference = self._registry.execute_mock_write(proposal)
                tool_scope.finish(TelemetryOutcome.SUCCESS)
                self._telemetry.record_tool_call(
                    tool_name=proposal.name,
                    tool_version=proposal.version,
                    outcome=TelemetryOutcome.SUCCESS,
                )
        except BaseException:
            unknown = _updated_approval(
                executing,
                status=ApprovalStatus.EXECUTION_UNKNOWN,
                revision=executing.revision + 1,
                terminal_at=datetime.now(UTC),
                safe_error_code="internal_error",
            )
            self._store.finish(
                unknown,
                expected_revision=executing.revision,
                maximum_bytes=maximum_bytes,
            )
            raise
        consumed = _updated_approval(
            executing,
            status=ApprovalStatus.CONSUMED,
            revision=executing.revision + 1,
            terminal_at=datetime.now(UTC),
            result_reference_sha256=result_reference,
        )
        consumed = self._store.finish(
            consumed,
            expected_revision=executing.revision,
            maximum_bytes=maximum_bytes,
        )
        final_state = AgentState(
            revision=2,
            request_id=request_id,
            run_id=consumed.run_id,
            tenant_reference_sha256=consumed.tenant_reference_sha256,
            subject_reference_sha256=hash_identifier(auth_context.subject_id),
            authorization_reference_sha256=authorization_reference(auth_context),
            current_node=AgentNode.SAFE_TERMINAL,
            outcome=AgentOutcome.COMPLETED,
            terminal_reason=TerminalReason.WRITE_TOOL_COMPLETED,
            tool_name=consumed.tool_name,
            tool_version=consumed.tool_version,
            arguments_sha256=consumed.arguments_sha256,
            approval_id=consumed.approval_id,
            approval_status=consumed.status,
            approval_expires_at=consumed.expires_at,
            tool_call_count=1,
            idempotency_key_sha256=consumed.idempotency_key_sha256,
            result_reference_sha256=result_reference,
        )
        self._store.save_state(final_state, maximum_bytes=maximum_bytes)
        return AgentResult(
            request_id=request_id,
            run_id=consumed.run_id,
            approval_id=consumed.approval_id,
            outcome=AgentOutcome.COMPLETED,
            terminal_reason=TerminalReason.WRITE_TOOL_COMPLETED,
            result_reference_sha256=result_reference,
        )


def _telemetry_outcome(outcome: AgentOutcome) -> TelemetryOutcome:
    return {
        AgentOutcome.COMPLETED: TelemetryOutcome.SUCCESS,
        AgentOutcome.APPROVAL_REQUIRED: TelemetryOutcome.SUCCESS,
        AgentOutcome.DENIED: TelemetryOutcome.DENIED,
        AgentOutcome.REJECTED: TelemetryOutcome.REJECTED,
        AgentOutcome.EXPIRED: TelemetryOutcome.REJECTED,
        AgentOutcome.CANCELLED: TelemetryOutcome.CANCELLED,
        AgentOutcome.BUDGET_EXCEEDED: TelemetryOutcome.BUDGET_EXCEEDED,
        AgentOutcome.TIMED_OUT: TelemetryOutcome.TIMEOUT,
        AgentOutcome.SAFE_TERMINAL: TelemetryOutcome.ABSTAINED,
    }[outcome]
