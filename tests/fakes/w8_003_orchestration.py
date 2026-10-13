"""Deterministic offline adapters for W8-003 orchestration tests."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from enterprise_ai_platform.agent.authorization import authorization_reference
from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.orchestration.engine import OrchestrationEngine
from enterprise_ai_platform.orchestration.errors import (
    OrchestrationAuthorizationError,
    OrchestrationQuotaError,
    OrchestrationStateConflictError,
)
from enterprise_ai_platform.orchestration.models import (
    ApprovalDecision,
    ApprovalRequirement,
    ApprovalStatus,
    CompensationResult,
    CostClass,
    DeadLetterRecord,
    EventBridgeEnvelope,
    FailureClass,
    IdempotencyReservation,
    ReservationStatus,
    TaskDisposition,
    TaskResult,
    WorkflowExecutionState,
    WorkflowKind,
    WorkflowRequest,
    WorkflowTransition,
)
from enterprise_ai_platform.orchestration.policy import OrchestrationPolicy, load_workflow_policy
from enterprise_ai_platform.retrieval.models import (
    CLASSIFICATION_RANK,
    AuthContext,
    Classification,
    Role,
)
from enterprise_ai_platform.serving.models import (
    ArtifactApprovalState,
    ArtifactIdentity,
    ModelClass,
    ServingProvider,
)

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "configs" / "orchestration" / "async-workflow-policy.yaml"
FIXED_NOW = datetime(2026, 10, 13, 8, 0, tzinfo=UTC)
WORKFLOW_ID = UUID("11111111-1111-4111-8111-111111111111")
EVENT_ID = UUID("22222222-2222-4222-8222-222222222222")
CORRELATION_ID = UUID("33333333-3333-4333-8333-333333333333")


@dataclass(slots=True)
class FakeClock:
    current: datetime = FIXED_NOW
    sleeps: list[float] = field(default_factory=list)

    def __call__(self) -> datetime:
        return self.current

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.current += timedelta(seconds=seconds)


@dataclass(slots=True)
class FakeAuthorizationGate:
    clock: FakeClock
    calls: int = 0

    async def authorize(
        self,
        *,
        workflow_kind: WorkflowKind,
        tenant_reference_sha256: str,
        subject_reference_sha256: str,
        authorization_reference_sha256: str,
        classification: Classification,
        auth_context: AuthContext,
    ) -> None:
        self.calls += 1
        required_roles = {
            WorkflowKind.ASYNCHRONOUS_INFERENCE: {Role.READER, Role.ADMIN},
            WorkflowKind.LONG_RUNNING_INGESTION: {Role.INGESTOR, Role.ADMIN},
            WorkflowKind.MODEL_TRAINING: {Role.ADMIN},
        }[workflow_kind]
        if (
            not auth_context.is_active(self.clock())
            or hash_identifier(auth_context.tenant_id) != tenant_reference_sha256
            or hash_identifier(auth_context.subject_id) != subject_reference_sha256
            or authorization_reference(auth_context) != authorization_reference_sha256
            or not auth_context.roles.intersection(required_roles)
            or CLASSIFICATION_RANK[auth_context.clearance] < CLASSIFICATION_RANK[classification]
        ):
            raise OrchestrationAuthorizationError


@dataclass(slots=True)
class InMemoryStateStore:
    states: dict[UUID, WorkflowExecutionState] = field(default_factory=dict)

    async def create(self, state: WorkflowExecutionState) -> None:
        if state.workflow_id in self.states:
            raise OrchestrationStateConflictError
        self.states[state.workflow_id] = state

    async def load(self, workflow_id: UUID) -> WorkflowExecutionState | None:
        return self.states.get(workflow_id)

    async def compare_and_swap(self, expected_revision: int, state: WorkflowExecutionState) -> None:
        current = self.states.get(state.workflow_id)
        if current is None or current.revision != expected_revision:
            raise OrchestrationStateConflictError
        self.states[state.workflow_id] = state


@dataclass(slots=True)
class InMemoryIdempotencyStore:
    bindings: dict[str, str] = field(default_factory=dict)
    results: dict[str, WorkflowExecutionState] = field(default_factory=dict)
    in_progress: set[str] = field(default_factory=set)

    async def reserve(self, key: str, binding_sha256: str) -> IdempotencyReservation:
        existing = self.bindings.get(key)
        if existing is None:
            self.bindings[key] = binding_sha256
            self.in_progress.add(key)
            return IdempotencyReservation(status=ReservationStatus.NEW)
        if existing != binding_sha256:
            return IdempotencyReservation(status=ReservationStatus.CONFLICT)
        if key in self.results:
            return IdempotencyReservation(
                status=ReservationStatus.REPLAY,
                prior_state=self.results[key],
            )
        return IdempotencyReservation(status=ReservationStatus.IN_PROGRESS)

    async def complete(self, key: str, state: WorkflowExecutionState) -> None:
        self.results.setdefault(key, state)
        self.in_progress.discard(key)


@dataclass(slots=True)
class InMemoryQuotaGate:
    maximum_global: int = 4
    maximum_per_tenant: int = 2
    active_global: int = 0
    active_by_tenant: dict[str, int] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def reserve(self, tenant_reference_sha256: str) -> InMemoryQuotaLease:
        async with self._lock:
            tenant_active = self.active_by_tenant.get(tenant_reference_sha256, 0)
            if (
                self.active_global >= self.maximum_global
                or tenant_active >= self.maximum_per_tenant
            ):
                raise OrchestrationQuotaError
            self.active_global += 1
            self.active_by_tenant[tenant_reference_sha256] = tenant_active + 1
        return InMemoryQuotaLease(self, tenant_reference_sha256)

    async def _release(self, tenant_reference_sha256: str) -> None:
        async with self._lock:
            current = self.active_by_tenant.get(tenant_reference_sha256, 0)
            if current < 1 or self.active_global < 1:
                raise OrchestrationStateConflictError
            self.active_global -= 1
            if current == 1:
                self.active_by_tenant.pop(tenant_reference_sha256)
            else:
                self.active_by_tenant[tenant_reference_sha256] = current - 1


@dataclass(slots=True)
class InMemoryQuotaLease:
    gate: InMemoryQuotaGate
    tenant_reference_sha256: str
    released: bool = False

    async def release(self) -> None:
        if not self.released:
            await self.gate._release(self.tenant_reference_sha256)
            self.released = True


@dataclass(slots=True)
class FakeApprovalGate:
    clock: FakeClock
    status: ApprovalStatus = ApprovalStatus.APPROVED
    calls: int = 0

    async def decide(self, state: WorkflowExecutionState) -> ApprovalDecision:
        self.calls += 1
        expired = self.status is ApprovalStatus.EXPIRED
        return ApprovalDecision(
            status=self.status,
            approval_reference_sha256="c" * 64,
            tenant_reference_sha256=state.tenant_reference_sha256,
            requester_reference_sha256=state.subject_reference_sha256,
            approver_reference_sha256="d" * 64,
            request_identity_sha256=state.request_identity_sha256,
            decided_at=self.clock() - timedelta(seconds=600) if expired else self.clock(),
            expires_at=self.clock() if expired else self.clock() + timedelta(seconds=600),
        )


@dataclass(slots=True)
class FakeTaskExecutor:
    results: list[TaskResult] = field(
        default_factory=lambda: [
            TaskResult(
                disposition=TaskDisposition.SUCCESS,
                result_reference_sha256="e" * 64,
            )
        ]
    )
    calls: list[WorkflowExecutionState] = field(default_factory=list)

    async def execute(self, state: WorkflowExecutionState) -> TaskResult:
        self.calls.append(state)
        if not self.results:
            raise AssertionError("fake task result sequence exhausted")
        return self.results.pop(0)


@dataclass(slots=True)
class RecordingAuditSink:
    transitions: list[WorkflowTransition] = field(default_factory=list)

    async def write(self, transition: WorkflowTransition) -> None:
        self.transitions.append(transition)


@dataclass(slots=True)
class RecordingDeadLetterSink:
    fail: bool = False
    records: list[DeadLetterRecord] = field(default_factory=list)

    async def write(self, record: DeadLetterRecord) -> None:
        if self.fail:
            raise RuntimeError("synthetic dead-letter failure")
        self.records.append(record)


@dataclass(slots=True)
class FakeCompensator:
    succeed: bool = True
    calls: list[tuple[WorkflowExecutionState, str]] = field(default_factory=list)

    async def compensate(
        self, state: WorkflowExecutionState, effect_reference_sha256: str
    ) -> CompensationResult:
        self.calls.append((state, effect_reference_sha256))
        if self.succeed:
            return CompensationResult(
                succeeded=True,
                compensation_reference_sha256="f" * 64,
            )
        return CompensationResult(succeeded=False, safe_reason_code="COMPENSATION_FAILED")


def make_policy() -> OrchestrationPolicy:
    return load_workflow_policy(POLICY_PATH)


def make_auth(
    *,
    tenant_id: str = "tenant-a",
    subject_id: str = "subject-a",
    roles: frozenset[Role] = frozenset({Role.ADMIN}),
    clearance: Classification = Classification.RESTRICTED,
) -> AuthContext:
    return AuthContext(
        subject_id=subject_id,
        tenant_id=tenant_id,
        roles=roles,
        clearance=clearance,
        groups=frozenset(),
        issuer="https://identity.example.invalid",
        audience="enterprise-ai-platform",
        expires_at=FIXED_NOW + timedelta(hours=1),
        request_id="request-a",
    )


def make_artifact(
    *,
    model_class: ModelClass = ModelClass.FOUNDATION,
    tenant_id: str = "tenant-a",
    classification: Classification = Classification.INTERNAL,
    approval_state: ArtifactApprovalState = ArtifactApprovalState.APPROVED,
) -> ArtifactIdentity:
    return ArtifactIdentity(
        model_class=model_class,
        artifact_name="approved-model",
        artifact_version="1",
        artifact_digest="a" * 64,
        source_uri="approved://model/1",
        license="Apache-2.0",
        approval_state=approval_state,
        approval_reference="ADR-019-approval-1",
        tenant_scope=tenant_id,
        classification=classification.value,
        processing_region="ap-southeast-1",
        training_identity_reference="training-role-1",
        inference_identity_reference="inference-role-1",
    )


def make_event(
    policy: OrchestrationPolicy,
    auth: AuthContext,
    *,
    kind: WorkflowKind = WorkflowKind.ASYNCHRONOUS_INFERENCE,
    classification: Classification = Classification.INTERNAL,
    approval_requirement: ApprovalRequirement = ApprovalRequirement.NONE,
    approval_state_artifact: ArtifactApprovalState = ArtifactApprovalState.APPROVED,
    requested_provider: ServingProvider | None = None,
    idempotency_key: str = "b" * 64,
    workflow_id: UUID = WORKFLOW_ID,
    cost_class: CostClass = CostClass.STANDARD,
) -> EventBridgeEnvelope:
    artifact = None
    if kind is not WorkflowKind.LONG_RUNNING_INGESTION:
        artifact = make_artifact(
            model_class=(
                ModelClass.FOUNDATION
                if kind is WorkflowKind.ASYNCHRONOUS_INFERENCE
                else ModelClass.CUSTOM
            ),
            tenant_id=auth.tenant_id,
            classification=classification,
            approval_state=approval_state_artifact,
        )
    if kind is WorkflowKind.MODEL_TRAINING:
        approval_requirement = ApprovalRequirement.TRAINING
        cost_class = CostClass.HIGH
    detail_types = {
        WorkflowKind.ASYNCHRONOUS_INFERENCE: "AsynchronousInferenceRequested",
        WorkflowKind.LONG_RUNNING_INGESTION: "LongRunningIngestionRequested",
        WorkflowKind.MODEL_TRAINING: "ModelTrainingRequested",
    }
    request = WorkflowRequest(
        workflow_id=workflow_id,
        workflow_kind=kind,
        correlation_id=CORRELATION_ID,
        idempotency_key=idempotency_key,
        tenant_reference_sha256=hash_identifier(auth.tenant_id),
        subject_reference_sha256=hash_identifier(auth.subject_id),
        authorization_reference_sha256=authorization_reference(auth),
        classification=classification,
        input_reference_sha256="9" * 64,
        policy_sha256=policy.identity_sha256,
        artifact=artifact,
        requested_provider=requested_provider,
        approval_requirement=approval_requirement,
        cost_class=cost_class,
        cost_estimate_reference_sha256=("8" * 64 if cost_class is CostClass.HIGH else None),
        requested_at=FIXED_NOW,
        deadline_at=FIXED_NOW + timedelta(seconds=policy.timeouts.for_kind(kind).workflow_seconds),
    )
    return EventBridgeEnvelope(
        id=EVENT_ID,
        detail_type=detail_types[kind],
        account="000000000000",
        time=FIXED_NOW,
        resources=(),
        detail=request,
    )


@dataclass(slots=True)
class EngineHarness:
    clock: FakeClock
    authorization: FakeAuthorizationGate
    states: InMemoryStateStore
    idempotency: InMemoryIdempotencyStore
    quota: InMemoryQuotaGate
    approval: FakeApprovalGate
    executor: FakeTaskExecutor
    audit: RecordingAuditSink
    dead_letter: RecordingDeadLetterSink
    compensator: FakeCompensator


def make_harness() -> EngineHarness:
    clock = FakeClock()
    return EngineHarness(
        clock=clock,
        authorization=FakeAuthorizationGate(clock),
        states=InMemoryStateStore(),
        idempotency=InMemoryIdempotencyStore(),
        quota=InMemoryQuotaGate(),
        approval=FakeApprovalGate(clock),
        executor=FakeTaskExecutor(),
        audit=RecordingAuditSink(),
        dead_letter=RecordingDeadLetterSink(),
        compensator=FakeCompensator(),
    )


def transient_failure() -> TaskResult:
    return TaskResult(
        disposition=TaskDisposition.RETRYABLE_FAILURE,
        failure_class=FailureClass.TRANSIENT_DEPENDENCY,
        safe_reason_code="TRANSIENT_DEPENDENCY",
    )


def permanent_failure() -> TaskResult:
    return TaskResult(
        disposition=TaskDisposition.PERMANENT_FAILURE,
        failure_class=FailureClass.PERMANENT_DEPENDENCY,
        safe_reason_code="PERMANENT_DEPENDENCY",
    )


def make_engine(policy: OrchestrationPolicy, harness: EngineHarness) -> OrchestrationEngine:
    return OrchestrationEngine(
        policy=policy,
        authorization_gate=harness.authorization,
        state_store=harness.states,
        idempotency_store=harness.idempotency,
        quota_gate=harness.quota,
        approval_gate=harness.approval,
        task_executor=harness.executor,
        audit_sink=harness.audit,
        dead_letter_sink=harness.dead_letter,
        compensator=harness.compensator,
        clock=harness.clock,
        sleeper=harness.clock.sleep,
    )
