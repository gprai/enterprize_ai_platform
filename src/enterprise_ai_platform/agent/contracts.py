"""Provider-neutral injected contracts for the bounded agent workflow."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from enterprise_ai_platform.retrieval.models import AuthContext

from .errors import AgentNotConfiguredError
from .models import (
    AgentCommand,
    AgentResult,
    AgentState,
    AnswerReference,
    ApprovalRecord,
    EvidenceGrade,
    EvidencePacket,
    ToolProposal,
)


@runtime_checkable
class AgentEvidenceGateway(Protocol):
    """Thin provider-neutral seam; live W2/W3 adaptation remains deferred."""

    async def retrieve(
        self,
        auth_context: AuthContext,
        query: str,
    ) -> EvidencePacket: ...

    async def grade_evidence(
        self,
        auth_context: AuthContext,
        evidence: EvidencePacket,
    ) -> EvidenceGrade: ...

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        evidence: EvidencePacket,
    ) -> AnswerReference: ...


@runtime_checkable
class AgentPlanner(Protocol):
    """Injected deterministic proposal seam with no authority of its own."""

    async def propose(
        self,
        auth_context: AuthContext,
        query: str,
        answer: AnswerReference,
    ) -> ToolProposal | None: ...


@runtime_checkable
class LocalStatusProvider(Protocol):
    async def query_wiring_status(self) -> str: ...


@runtime_checkable
class AgentStateStore(Protocol):
    def save_state(self, state: AgentState, *, maximum_bytes: int) -> None: ...

    def create_approval(
        self,
        record: ApprovalRecord,
        *,
        maximum_bytes: int,
    ) -> None: ...

    def get_approval(
        self,
        approval_id: str,
        *,
        maximum_bytes: int,
    ) -> ApprovalRecord | None: ...

    def approve(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord: ...

    def claim(
        self,
        approval_id: str,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord: ...

    def terminate_pending(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord: ...

    def finish(
        self,
        record: ApprovalRecord,
        *,
        expected_revision: int,
        maximum_bytes: int,
    ) -> ApprovalRecord: ...

    def purge(self, *, before_epoch: int, maximum_records: int) -> int: ...


@runtime_checkable
class AgentController(Protocol):
    async def handle(
        self,
        transport: AgentCommand,
        auth_context: AuthContext,
        request_id: str,
    ) -> AgentResult: ...


class UnconfiguredAgentEvidenceGateway:
    async def retrieve(
        self,
        auth_context: AuthContext,
        query: str,
    ) -> EvidencePacket:
        del auth_context, query
        raise AgentNotConfiguredError

    async def grade_evidence(
        self,
        auth_context: AuthContext,
        evidence: EvidencePacket,
    ) -> EvidenceGrade:
        del auth_context, evidence
        raise AgentNotConfiguredError

    async def answer(
        self,
        auth_context: AuthContext,
        query: str,
        evidence: EvidencePacket,
    ) -> AnswerReference:
        del auth_context, query, evidence
        raise AgentNotConfiguredError


class UnconfiguredAgentPlanner:
    async def propose(
        self,
        auth_context: AuthContext,
        query: str,
        answer: AnswerReference,
    ) -> ToolProposal | None:
        del auth_context, query, answer
        raise AgentNotConfiguredError


class UnconfiguredLocalStatusProvider:
    async def query_wiring_status(self) -> str:
        raise AgentNotConfiguredError
