"""Deterministic local-only collaborators for W4-002 automated tests."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from enterprise_ai_platform.agent.errors import AgentApprovalConflictError
from enterprise_ai_platform.agent.models import (
    AgentCommand,
    AgentResult,
    AgentState,
    AnswerReference,
    ApprovalRecord,
    ApprovalStatus,
    EvidenceGrade,
    EvidencePacket,
    ToolProposal,
)
from enterprise_ai_platform.retrieval.models import AuthContext


class FakeAgentGateway:
    def __init__(
        self,
        *,
        evidence: EvidencePacket,
        grade: EvidenceGrade,
        answer: AnswerReference,
    ) -> None:
        self.evidence = evidence
        self.grade = grade
        self.answer_reference = answer
        self.calls: list[str] = []

    async def retrieve(
        self,
        auth_context: AuthContext,
        query: str,
    ) -> EvidencePacket:
        del auth_context, query
        self.calls.append("retrieve")
        return self.evidence.model_copy(deep=True)

    async def grade_evidence(
        self,
        auth_context: AuthContext,
        evidence: EvidencePacket,
    ) -> EvidenceGrade:
        del auth_context, evidence
        self.calls.append("grade_evidence")
        return self.grade.model_copy(deep=True)

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        evidence: EvidencePacket,
    ) -> AnswerReference:
        del auth_context, query, evidence
        self.calls.append("answer")
        return self.answer_reference.model_copy(deep=True)


class FakeAgentPlanner:
    def __init__(self, proposal: ToolProposal | None) -> None:
        self.proposal = proposal
        self.calls = 0

    async def propose(
        self,
        auth_context: AuthContext,
        query: str,
        answer: AnswerReference,
    ) -> ToolProposal | None:
        del auth_context, query, answer
        self.calls += 1
        return None if self.proposal is None else self.proposal.model_copy(deep=True)


class FakeLocalStatusProvider:
    def __init__(self, status: str = "ready") -> None:
        self.status = status
        self.calls = 0

    async def query_wiring_status(self) -> str:
        self.calls += 1
        return self.status


class InMemoryAgentStore:
    def __init__(self) -> None:
        self.states: list[AgentState] = []
        self.approvals: dict[str, ApprovalRecord] = {}

    def save_state(self, state: AgentState, *, maximum_bytes: int) -> None:
        del maximum_bytes
        validated = AgentState.model_validate(
            state.model_dump(mode="python"),
            strict=True,
        )
        self.states.append(validated)

    def create_approval(
        self,
        record: ApprovalRecord,
        *,
        maximum_bytes: int,
    ) -> None:
        del maximum_bytes
        record = ApprovalRecord.model_validate(
            record.model_dump(mode="python"),
            strict=True,
        )
        key = str(record.approval_id)
        if key in self.approvals:
            raise AgentApprovalConflictError
        self.approvals[key] = record.model_copy(deep=True)

    def get_approval(
        self,
        approval_id: str,
        *,
        maximum_bytes: int,
    ) -> ApprovalRecord | None:
        del maximum_bytes
        record = self.approvals.get(approval_id)
        return None if record is None else record.model_copy(deep=True)

    def _replace(
        self,
        record: ApprovalRecord,
        expected_revision: int,
        expected_status: ApprovalStatus,
    ) -> ApprovalRecord:
        record = ApprovalRecord.model_validate(
            record.model_dump(mode="python"),
            strict=True,
        )
        key = str(record.approval_id)
        current = self.approvals.get(key)
        if (
            current is None
            or current.revision != expected_revision
            or current.status is not expected_status
        ):
            raise AgentApprovalConflictError
        self.approvals[key] = record.model_copy(deep=True)
        return record

    def approve(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        del maximum_bytes
        return self._replace(record, expected_revision, ApprovalStatus.PENDING)

    def claim(
        self,
        approval_id: str,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        del maximum_bytes
        current = self.approvals[approval_id]
        values = current.model_dump(mode="python")
        values.update(
            status=ApprovalStatus.EXECUTING,
            revision=current.revision + 1,
        )
        executing = ApprovalRecord.model_validate(values, strict=True)
        return self._replace(executing, expected_revision, ApprovalStatus.APPROVED)

    def terminate_pending(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        del maximum_bytes
        return self._replace(record, expected_revision, ApprovalStatus.PENDING)

    def finish(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord:
        del maximum_bytes
        return self._replace(record, expected_revision, ApprovalStatus.EXECUTING)

    def purge(self, *, before_epoch: int, maximum_records: int) -> int:
        del before_epoch, maximum_records
        return 0


@dataclass(frozen=True, slots=True)
class AgentControllerCall:
    transport: AgentCommand
    auth_context: AuthContext
    request_id: str


class FakeAgentController:
    def __init__(self, result: AgentResult | BaseException) -> None:
        self.result = result
        self.calls: list[AgentControllerCall] = []

    async def handle(
        self,
        transport: AgentCommand,
        auth_context: AuthContext,
        request_id: str,
    ) -> AgentResult:
        self.calls.append(
            AgentControllerCall(
                transport=transport.model_copy(deep=True),
                auth_context=auth_context.model_copy(deep=True),
                request_id=request_id,
            )
        )
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result.model_copy(
            update={"request_id": UUID(request_id)},
            deep=True,
        )
