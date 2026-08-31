"""Same-tenant, distinct-reviewer, one-time W4-002 approval tests."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from enterprise_ai_platform.agent.controller import BoundedAgentController
from enterprise_ai_platform.agent.errors import (
    AgentApprovalConflictError,
    AgentAuthorizationError,
)
from enterprise_ai_platform.agent.models import (
    AgentBudgets,
    AgentOutcome,
    AnswerReference,
    ApprovalStatus,
    DecideAgentCommand,
    EvidenceGrade,
    EvidencePacket,
    MockSetServiceModeArguments,
    StartAgentCommand,
    ToolKind,
    ToolProposal,
)
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


def _auth(subject: str, tenant: str, *roles: Role) -> AuthContext:
    return AuthContext(
        subject_id=subject,
        tenant_id=tenant,
        roles=frozenset(roles),
        clearance=Classification.INTERNAL,
    )


def _controller(store: InMemoryAgentStore) -> BoundedAgentController:
    proposal = ToolProposal(
        name="mock_set_service_mode",
        kind=ToolKind.MOCK_WRITE,
        arguments=MockSetServiceModeArguments(mode="maintenance"),
    )
    return BoundedAgentController(
        gateway=FakeAgentGateway(
            evidence=EvidencePacket(references=("a" * 64,)),
            grade=EvidenceGrade(authorized=True, sufficient=True),
            answer=AnswerReference(result_reference_sha256="b" * 64, total_tokens=5),
        ),
        planner=FakeAgentPlanner(proposal),
        status_provider=FakeLocalStatusProvider(),
        store=store,
        budgets=AgentBudgets(),
        mock_write_enabled=True,
    )


def _decision(approval_id: object) -> DecideAgentCommand:
    return DecideAgentCommand(
        approval_id=approval_id,
        idempotency_key=uuid4(),
        tool_name="mock_set_service_mode",
        tool_version="1.0",
        arguments=MockSetServiceModeArguments(mode="maintenance"),
    )


def test_valid_distinct_reviewer_consumes_approval_once() -> None:
    store = InMemoryAgentStore()
    controller = _controller(store)
    requester = _auth("requester", "tenant-a", Role.ADMIN)
    reviewer = _auth("reviewer", "tenant-a", Role.REVIEWER)
    start = asyncio.run(
        controller.handle(StartAgentCommand(query="write proposal"), requester, str(uuid4()))
    )
    assert start.approval_id is not None
    decision = _decision(start.approval_id)

    completed = asyncio.run(controller.handle(decision, reviewer, str(uuid4())))
    assert completed.terminal_reason.value == "write_tool_completed"
    with pytest.raises(AgentApprovalConflictError):
        asyncio.run(controller.handle(decision, reviewer, str(uuid4())))


@pytest.mark.parametrize(
    "approver",
    [
        _auth("requester", "tenant-a", Role.REVIEWER),
        _auth("reviewer", "tenant-b", Role.REVIEWER),
        _auth("reader", "tenant-a", Role.READER),
    ],
)
def test_self_cross_tenant_and_nonreviewer_approval_are_denied(
    approver: AuthContext,
) -> None:
    store = InMemoryAgentStore()
    controller = _controller(store)
    start = asyncio.run(
        controller.handle(
            StartAgentCommand(query="write proposal"),
            _auth("requester", "tenant-a", Role.ADMIN),
            str(uuid4()),
        )
    )
    assert start.approval_id is not None
    with pytest.raises(AgentAuthorizationError):
        asyncio.run(controller.handle(_decision(start.approval_id), approver, str(uuid4())))


def test_altered_tool_arguments_are_rejected_before_execution() -> None:
    store = InMemoryAgentStore()
    controller = _controller(store)
    start = asyncio.run(
        controller.handle(
            StartAgentCommand(query="write proposal"),
            _auth("requester", "tenant-a", Role.ADMIN),
            str(uuid4()),
        )
    )
    assert start.approval_id is not None
    record = store.approvals[str(start.approval_id)]
    store.approvals[str(start.approval_id)] = record.model_copy(
        update={"arguments_sha256": "f" * 64}
    )
    with pytest.raises(AgentApprovalConflictError):
        asyncio.run(
            controller.handle(
                _decision(start.approval_id),
                _auth("reviewer", "tenant-a", Role.REVIEWER),
                str(uuid4()),
            )
        )


def test_missing_and_expired_approval_fail_closed() -> None:
    store = InMemoryAgentStore()
    controller = _controller(store)
    reviewer = _auth("reviewer", "tenant-a", Role.REVIEWER)
    with pytest.raises(AgentApprovalConflictError):
        asyncio.run(controller.handle(_decision(uuid4()), reviewer, str(uuid4())))

    start = asyncio.run(
        controller.handle(
            StartAgentCommand(query="write proposal"),
            _auth("requester", "tenant-a", Role.ADMIN),
            str(uuid4()),
        )
    )
    assert start.approval_id is not None
    pending = store.approvals[str(start.approval_id)]
    now = datetime.now(UTC)
    store.approvals[str(start.approval_id)] = pending.model_copy(
        update={
            "created_at": now - timedelta(minutes=20),
            "expires_at": now - timedelta(minutes=10),
        }
    )
    result = asyncio.run(controller.handle(_decision(start.approval_id), reviewer, str(uuid4())))
    assert result.outcome is AgentOutcome.EXPIRED
    assert store.approvals[str(start.approval_id)].status is ApprovalStatus.EXPIRED


@pytest.mark.parametrize(
    "status",
    [ApprovalStatus.REJECTED, ApprovalStatus.CANCELLED],
)
def test_rejected_and_cancelled_approval_return_safe_terminal(
    status: ApprovalStatus,
) -> None:
    store = InMemoryAgentStore()
    controller = _controller(store)
    start = asyncio.run(
        controller.handle(
            StartAgentCommand(query="write proposal"),
            _auth("requester", "tenant-a", Role.ADMIN),
            str(uuid4()),
        )
    )
    assert start.approval_id is not None
    pending = store.approvals[str(start.approval_id)]
    terminal = pending.model_copy(
        update={
            "status": status,
            "revision": 2,
            "terminal_at": datetime.now(UTC),
        }
    )
    store.terminate_pending(terminal, expected_revision=1, maximum_bytes=16_384)

    result = asyncio.run(
        controller.handle(
            _decision(start.approval_id),
            _auth("reviewer", "tenant-a", Role.REVIEWER),
            str(uuid4()),
        )
    )
    expected = {
        ApprovalStatus.REJECTED: AgentOutcome.REJECTED,
        ApprovalStatus.CANCELLED: AgentOutcome.CANCELLED,
    }
    assert result.outcome is expected[status]
    assert store.approvals[str(start.approval_id)].status is status
