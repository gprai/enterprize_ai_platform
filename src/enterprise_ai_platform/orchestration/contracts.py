"""Provider-neutral protocols for durable orchestration adapters."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Protocol
from uuid import UUID

from enterprise_ai_platform.retrieval.models import AuthContext, Classification

from .models import (
    ApprovalDecision,
    CompensationResult,
    DeadLetterRecord,
    IdempotencyReservation,
    TaskResult,
    WorkflowExecutionState,
    WorkflowKind,
    WorkflowTransition,
)

Clock = Callable[[], datetime]
Sleeper = Callable[[float], Awaitable[None]]


class AuthorizationGate(Protocol):
    async def authorize(
        self,
        *,
        workflow_kind: WorkflowKind,
        tenant_reference_sha256: str,
        subject_reference_sha256: str,
        authorization_reference_sha256: str,
        classification: Classification,
        auth_context: AuthContext,
    ) -> None: ...


class StateStore(Protocol):
    async def create(self, state: WorkflowExecutionState) -> None: ...
    async def load(self, workflow_id: UUID) -> WorkflowExecutionState | None: ...
    async def compare_and_swap(
        self, expected_revision: int, state: WorkflowExecutionState
    ) -> None: ...


class IdempotencyStore(Protocol):
    async def reserve(self, key: str, binding_sha256: str) -> IdempotencyReservation: ...
    async def complete(self, key: str, state: WorkflowExecutionState) -> None: ...


class QuotaLease(Protocol):
    async def release(self) -> None: ...


class QuotaGate(Protocol):
    async def reserve(self, tenant_reference_sha256: str) -> QuotaLease: ...


class ApprovalGate(Protocol):
    async def decide(self, state: WorkflowExecutionState) -> ApprovalDecision: ...


class TaskExecutor(Protocol):
    async def execute(self, state: WorkflowExecutionState) -> TaskResult: ...


class AuditSink(Protocol):
    async def write(self, transition: WorkflowTransition) -> None: ...


class DeadLetterSink(Protocol):
    async def write(self, record: DeadLetterRecord) -> None: ...


class Compensator(Protocol):
    async def compensate(
        self, state: WorkflowExecutionState, effect_reference_sha256: str
    ) -> CompensationResult: ...
