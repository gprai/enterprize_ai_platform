"""Deterministic provider-neutral coordinator for W8-003 workflows."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import UUID

from enterprise_ai_platform.retrieval.models import AuthContext
from enterprise_ai_platform.serving.errors import ServingError
from enterprise_ai_platform.serving.models import ServingProvider, ServingRequest
from enterprise_ai_platform.serving.routing import route_artifact, validate_request_authorization

from .contracts import (
    ApprovalGate,
    AuditSink,
    AuthorizationGate,
    Clock,
    Compensator,
    DeadLetterSink,
    IdempotencyStore,
    QuotaGate,
    Sleeper,
    StateStore,
    TaskExecutor,
)
from .errors import (
    OrchestrationApprovalError,
    OrchestrationIdempotencyError,
    OrchestrationProviderError,
    OrchestrationQuotaError,
    OrchestrationResumeError,
    OrchestrationStateConflictError,
    OrchestrationValidationError,
)
from .models import (
    TERMINAL_STATES,
    ApprovalStatus,
    DeadLetterRecord,
    EventBridgeEnvelope,
    FailureClass,
    ReservationStatus,
    ResumeAction,
    TaskDisposition,
    TaskResult,
    WorkflowExecutionState,
    WorkflowKind,
    WorkflowState,
    WorkflowTransition,
)
from .policy import OrchestrationPolicy
from .serialization import canonical_bytes, fingerprint

_ALLOWED_TRANSITIONS: dict[WorkflowState | None, frozenset[WorkflowState]] = {
    None: frozenset({WorkflowState.RECEIVED}),
    WorkflowState.RECEIVED: frozenset({WorkflowState.AUTHORIZED}),
    WorkflowState.AUTHORIZED: frozenset({WorkflowState.IDEMPOTENCY_RESERVED}),
    WorkflowState.IDEMPOTENCY_RESERVED: frozenset(
        {WorkflowState.QUOTA_RESERVED, WorkflowState.DENIED}
    ),
    WorkflowState.QUOTA_RESERVED: frozenset(
        {WorkflowState.AWAITING_APPROVAL, WorkflowState.READY, WorkflowState.DENIED}
    ),
    WorkflowState.AWAITING_APPROVAL: frozenset(
        {
            WorkflowState.READY,
            WorkflowState.DENIED,
            WorkflowState.TIMED_OUT,
            WorkflowState.CANCELLED,
        }
    ),
    WorkflowState.READY: frozenset(
        {WorkflowState.RUNNING, WorkflowState.TIMED_OUT, WorkflowState.CANCELLED}
    ),
    WorkflowState.RUNNING: frozenset(
        {
            WorkflowState.SUCCEEDED,
            WorkflowState.RETRY_WAIT,
            WorkflowState.RECONCILIATION_REQUIRED,
            WorkflowState.COMPENSATING,
            WorkflowState.TIMED_OUT,
            WorkflowState.CANCELLED,
            WorkflowState.DEAD_LETTERED,
        }
    ),
    WorkflowState.RETRY_WAIT: frozenset(
        {
            WorkflowState.RUNNING,
            WorkflowState.READY,
            WorkflowState.TIMED_OUT,
            WorkflowState.CANCELLED,
        }
    ),
    WorkflowState.RECONCILIATION_REQUIRED: frozenset(
        {
            WorkflowState.READY,
            WorkflowState.COMPENSATING,
            WorkflowState.DEAD_LETTERED,
            WorkflowState.TIMED_OUT,
            WorkflowState.CANCELLED,
        }
    ),
    WorkflowState.COMPENSATING: frozenset(
        {
            WorkflowState.COMPENSATED,
            WorkflowState.RECONCILIATION_REQUIRED,
            WorkflowState.DEAD_LETTERED,
        }
    ),
}


class OrchestrationEngine:
    """Coordinate bounded work without creating cloud or provider resources."""

    def __init__(
        self,
        *,
        policy: OrchestrationPolicy,
        authorization_gate: AuthorizationGate,
        state_store: StateStore,
        idempotency_store: IdempotencyStore,
        quota_gate: QuotaGate,
        approval_gate: ApprovalGate,
        task_executor: TaskExecutor,
        audit_sink: AuditSink,
        dead_letter_sink: DeadLetterSink,
        compensator: Compensator,
        clock: Clock,
        sleeper: Sleeper,
    ) -> None:
        self._policy = policy
        self._authorization_gate = authorization_gate
        self._state_store = state_store
        self._idempotency_store = idempotency_store
        self._quota_gate = quota_gate
        self._approval_gate = approval_gate
        self._task_executor = task_executor
        self._audit_sink = audit_sink
        self._dead_letter_sink = dead_letter_sink
        self._compensator = compensator
        self._clock = clock
        self._sleeper = sleeper
        self._accepting = True

    def withdraw_admission(self) -> None:
        """Stop new submissions without mutating work already in progress."""

        self._accepting = False

    async def submit(
        self, event: EventBridgeEnvelope, auth_context: AuthContext
    ) -> WorkflowExecutionState:
        if not self._accepting:
            raise OrchestrationValidationError
        if len(canonical_bytes(event)) > self._policy.limits.maximum_event_bytes:
            raise OrchestrationValidationError
        request = event.detail
        timeout = self._policy.timeouts.for_kind(request.workflow_kind)
        if request.policy_sha256 != self._policy.identity_sha256:
            raise OrchestrationValidationError
        now = self._clock()
        if (
            request.requested_at > now
            or now - request.requested_at > timedelta(hours=24)
            or request.deadline_at <= now
            or request.deadline_at - request.requested_at
            != timedelta(seconds=timeout.workflow_seconds)
        ):
            raise OrchestrationValidationError

        await self._authorization_gate.authorize(
            workflow_kind=request.workflow_kind,
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.subject_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=request.classification,
            auth_context=auth_context,
        )
        provider, artifact_identity, training_request_identity = self._admit_provider(
            event, auth_context
        )
        request_identity = fingerprint(request)
        reservation = await self._idempotency_store.reserve(
            request.idempotency_key,
            fingerprint(
                {
                    "request_identity_sha256": request_identity,
                    "tenant_reference_sha256": request.tenant_reference_sha256,
                    "workflow_kind": request.workflow_kind,
                }
            ),
        )
        if reservation.status is ReservationStatus.REPLAY:
            if reservation.prior_state is None:
                raise OrchestrationStateConflictError
            return reservation.prior_state
        if reservation.status is ReservationStatus.CONFLICT:
            raise OrchestrationIdempotencyError
        if reservation.status is ReservationStatus.IN_PROGRESS:
            raise OrchestrationResumeError

        initial = self._initial_state(
            event,
            request_identity=request_identity,
            artifact_identity=artifact_identity,
            training_request_identity=training_request_identity,
            provider=provider,
            task_timeout_seconds=timeout.task_seconds,
        )
        initial_transition = self._transition_record(None, initial)
        await self._state_store.create(initial)
        await self._audit_sink.write(initial_transition)
        state = await self._transition(initial, WorkflowState.AUTHORIZED, "AUTHORIZATION_PASS")
        state = await self._transition(
            state,
            WorkflowState.IDEMPOTENCY_RESERVED,
            "IDEMPOTENCY_RESERVED",
        )

        try:
            lease = await self._quota_gate.reserve(request.tenant_reference_sha256)
        except OrchestrationQuotaError:
            state = await self._transition(
                state,
                WorkflowState.DENIED,
                "TENANT_QUOTA_EXCEEDED",
                failure_class=FailureClass.TENANT_QUOTA_EXCEEDED,
            )
            await self._idempotency_store.complete(request.idempotency_key, state)
            return state

        try:
            state = await self._transition(state, WorkflowState.QUOTA_RESERVED, "QUOTA_RESERVED")
            if request.approval_requirement.value != "none":
                state = await self._transition(
                    state,
                    WorkflowState.AWAITING_APPROVAL,
                    "APPROVAL_REQUIRED",
                )
                state = await self._apply_approval(state)
                if state.state in TERMINAL_STATES:
                    await self._idempotency_store.complete(request.idempotency_key, state)
                    return state
            else:
                state = await self._transition(state, WorkflowState.READY, "WORKFLOW_READY")
            state = await self._run(state)
            if state.state in TERMINAL_STATES:
                await self._idempotency_store.complete(request.idempotency_key, state)
            return state
        finally:
            await lease.release()

    async def resume(
        self,
        *,
        workflow_id: UUID,
        expected_revision: int,
        resume_token_sha256: str,
        action: ResumeAction,
        auth_context: AuthContext,
    ) -> WorkflowExecutionState:
        state = await self._state_store.load(workflow_id)
        if (
            state is None
            or state.state is not WorkflowState.RECONCILIATION_REQUIRED
            or state.revision != expected_revision
            or state.resume_token_sha256 != resume_token_sha256
        ):
            raise OrchestrationResumeError
        await self._authorization_gate.authorize(
            workflow_kind=state.workflow_kind,
            tenant_reference_sha256=state.tenant_reference_sha256,
            subject_reference_sha256=state.subject_reference_sha256,
            authorization_reference_sha256=state.authorization_reference_sha256,
            classification=state.classification,
            auth_context=auth_context,
        )
        lease = await self._quota_gate.reserve(state.tenant_reference_sha256)
        try:
            if self._clock() >= state.deadline_at:
                result = await self._transition(
                    state,
                    WorkflowState.TIMED_OUT,
                    "WORKFLOW_TIMEOUT",
                    failure_class=FailureClass.WORKFLOW_TIMEOUT,
                    resume_token_sha256=None,
                )
            elif action is ResumeAction.RETRY:
                ready = await self._transition(
                    state,
                    WorkflowState.READY,
                    "OWNER_RETRY_AUTHORIZED",
                    resume_token_sha256=None,
                )
                result = await self._run(ready)
            elif action is ResumeAction.COMPENSATE:
                if state.effect_reference_sha256 is None:
                    raise OrchestrationResumeError
                compensating = await self._transition(
                    state,
                    WorkflowState.COMPENSATING,
                    "OWNER_COMPENSATION_AUTHORIZED",
                    resume_token_sha256=None,
                )
                result = await self._compensate(compensating, state.effect_reference_sha256)
            else:
                result = await self._dead_letter(
                    state,
                    FailureClass.DEPENDENCY_OUTCOME_UNKNOWN,
                    "OWNER_DEAD_LETTER_AUTHORIZED",
                )
            if result.state in TERMINAL_STATES:
                await self._idempotency_store.complete(state.idempotency_key, result)
            return result
        finally:
            await lease.release()

    async def cancel(self, workflow_id: UUID, auth_context: AuthContext) -> WorkflowExecutionState:
        state = await self._state_store.load(workflow_id)
        if state is None:
            raise OrchestrationResumeError
        await self._authorization_gate.authorize(
            workflow_kind=state.workflow_kind,
            tenant_reference_sha256=state.tenant_reference_sha256,
            subject_reference_sha256=state.subject_reference_sha256,
            authorization_reference_sha256=state.authorization_reference_sha256,
            classification=state.classification,
            auth_context=auth_context,
        )
        if state.state in TERMINAL_STATES:
            return state
        cancelled = await self._transition(
            state,
            WorkflowState.CANCELLED,
            "OWNER_CANCELLED",
            failure_class=FailureClass.CANCELLED,
            resume_token_sha256=None,
        )
        await self._idempotency_store.complete(state.idempotency_key, cancelled)
        return cancelled

    def _admit_provider(
        self, event: EventBridgeEnvelope, auth_context: AuthContext
    ) -> tuple[ServingProvider | None, str | None, str | None]:
        request = event.detail
        if request.workflow_kind is WorkflowKind.MODEL_TRAINING:
            if request.training_request_identity_sha256 is None:
                raise OrchestrationProviderError
            return None, None, request.training_request_identity_sha256
        if request.artifact is None:
            return None, None, None
        try:
            serving_request = ServingRequest(
                request_id=str(event.id),
                artifact=request.artifact,
                tenant_id=auth_context.tenant_id,
                classification=request.classification.value,
                authorized=True,
                payload={},
            )
            validate_request_authorization(serving_request)
            provider = route_artifact(request.artifact)
        except ServingError:
            raise OrchestrationProviderError from None
        if request.requested_provider is not None and request.requested_provider is not provider:
            raise OrchestrationProviderError
        return provider, request.artifact.canonical_digest(), None

    def _initial_state(
        self,
        event: EventBridgeEnvelope,
        *,
        request_identity: str,
        artifact_identity: str | None,
        training_request_identity: str | None,
        provider: ServingProvider | None,
        task_timeout_seconds: int,
    ) -> WorkflowExecutionState:
        request = event.detail
        now = self._clock()
        transition_hash = fingerprint(
            {
                "correlation_id": request.correlation_id,
                "next_state": WorkflowState.RECEIVED,
                "previous_state": None,
                "reason_code": "EVENT_RECEIVED",
                "tenant_reference_sha256": request.tenant_reference_sha256,
                "timestamp": now,
                "workflow_id": request.workflow_id,
            }
        )
        return WorkflowExecutionState(
            revision=1,
            event_id=event.id,
            workflow_id=request.workflow_id,
            workflow_kind=request.workflow_kind,
            state=WorkflowState.RECEIVED,
            correlation_id=request.correlation_id,
            idempotency_key=request.idempotency_key,
            tenant_reference_sha256=request.tenant_reference_sha256,
            subject_reference_sha256=request.subject_reference_sha256,
            authorization_reference_sha256=request.authorization_reference_sha256,
            classification=request.classification,
            input_reference_sha256=request.input_reference_sha256,
            policy_sha256=request.policy_sha256,
            request_identity_sha256=request_identity,
            artifact_identity_sha256=artifact_identity,
            training_request_identity_sha256=training_request_identity,
            provider=provider,
            task_timeout_seconds=task_timeout_seconds,
            deadline_at=request.deadline_at,
            safe_reason_code="EVENT_RECEIVED",
            latest_transition_sha256=transition_hash,
            created_at=now,
            updated_at=now,
        )

    def _transition_record(
        self,
        previous: WorkflowExecutionState | None,
        current: WorkflowExecutionState,
    ) -> WorkflowTransition:
        return WorkflowTransition(
            workflow_id=current.workflow_id,
            correlation_id=current.correlation_id,
            revision=current.revision,
            previous_state=None if previous is None else previous.state,
            next_state=current.state,
            safe_reason_code=current.safe_reason_code,
            failure_class=current.failure_class,
            tenant_reference_sha256=current.tenant_reference_sha256,
            prior_transition_sha256=(
                None if previous is None else previous.latest_transition_sha256
            ),
            transition_sha256=current.latest_transition_sha256,
            timestamp=current.updated_at,
        )

    async def _transition(
        self,
        state: WorkflowExecutionState,
        next_state: WorkflowState,
        reason: str,
        *,
        failure_class: FailureClass | None = None,
        **updates: object,
    ) -> WorkflowExecutionState:
        if (
            state.state in TERMINAL_STATES
            or next_state not in _ALLOWED_TRANSITIONS.get(state.state, frozenset())
            or state.transition_count >= self._policy.limits.maximum_transitions
        ):
            raise OrchestrationStateConflictError
        now = self._clock()
        completed_at = now if next_state in TERMINAL_STATES else None
        transition_hash = fingerprint(
            {
                "correlation_id": state.correlation_id,
                "failure_class": failure_class,
                "next_state": next_state,
                "previous_state": state.state,
                "prior_transition_sha256": state.latest_transition_sha256,
                "reason_code": reason,
                "tenant_reference_sha256": state.tenant_reference_sha256,
                "timestamp": now,
                "workflow_id": state.workflow_id,
            }
        )
        values = state.model_dump(mode="python")
        values.update(
            {
                "revision": state.revision + 1,
                "state": next_state,
                "transition_count": state.transition_count + 1,
                "safe_reason_code": reason,
                "failure_class": failure_class,
                "latest_transition_sha256": transition_hash,
                "updated_at": now,
                "completed_at": completed_at,
                "next_retry_at": None,
            }
        )
        values.update(updates)
        current = WorkflowExecutionState.model_validate(values, strict=True)
        if len(canonical_bytes(current)) > self._policy.limits.maximum_state_bytes:
            raise OrchestrationValidationError
        await self._state_store.compare_and_swap(state.revision, current)
        await self._audit_sink.write(self._transition_record(state, current))
        return current

    async def _apply_approval(self, state: WorkflowExecutionState) -> WorkflowExecutionState:
        decision = await self._approval_gate.decide(state)
        now = self._clock()
        if (
            decision.tenant_reference_sha256 != state.tenant_reference_sha256
            or decision.requester_reference_sha256 != state.subject_reference_sha256
            or decision.request_identity_sha256 != state.request_identity_sha256
            or decision.decided_at > now
            or decision.expires_at - decision.decided_at
            != timedelta(seconds=self._policy.approval.ttl_seconds)
        ):
            raise OrchestrationApprovalError
        if decision.status is ApprovalStatus.APPROVED:
            if decision.expires_at <= now:
                return await self._transition(
                    state,
                    WorkflowState.DENIED,
                    "APPROVAL_EXPIRED",
                    failure_class=FailureClass.APPROVAL_EXPIRED,
                    approval_reference_sha256=decision.approval_reference_sha256,
                    approval_status=ApprovalStatus.EXPIRED,
                )
            return await self._transition(
                state,
                WorkflowState.READY,
                "APPROVAL_GRANTED",
                approval_reference_sha256=decision.approval_reference_sha256,
                approval_status=decision.status,
            )
        if decision.status is ApprovalStatus.EXPIRED and decision.expires_at > now:
            raise OrchestrationApprovalError
        failure = (
            FailureClass.APPROVAL_EXPIRED
            if decision.status is ApprovalStatus.EXPIRED
            else FailureClass.APPROVAL_DENIED
        )
        reason = (
            "APPROVAL_EXPIRED" if failure is FailureClass.APPROVAL_EXPIRED else "APPROVAL_DENIED"
        )
        return await self._transition(
            state,
            WorkflowState.DENIED,
            reason,
            failure_class=failure,
            approval_reference_sha256=decision.approval_reference_sha256,
            approval_status=decision.status,
        )

    async def _run(self, state: WorkflowExecutionState) -> WorkflowExecutionState:
        delays = self._policy.retry.backoff_seconds
        while state.attempt_count < self._policy.retry.maximum_attempts:
            if self._clock() >= state.deadline_at:
                return await self._transition(
                    state,
                    WorkflowState.TIMED_OUT,
                    "WORKFLOW_TIMEOUT",
                    failure_class=FailureClass.WORKFLOW_TIMEOUT,
                )
            state = await self._transition(
                state,
                WorkflowState.RUNNING,
                "TASK_DISPATCHED",
                attempt_count=state.attempt_count + 1,
            )
            try:
                async with asyncio.timeout(state.task_timeout_seconds):
                    result = await self._task_executor.execute(state)
            except TimeoutError:
                result = TaskResult(
                    disposition=TaskDisposition.RETRYABLE_FAILURE,
                    failure_class=FailureClass.TASK_TIMEOUT,
                    safe_reason_code="TASK_TIMEOUT",
                )
            total_attempts = state.attempt_count + result.attempts_consumed - 1
            total_fanout = state.fanout_count + result.fanout_consumed
            if total_fanout > self._policy.limits.maximum_fanout:
                return await self._dead_letter(
                    state,
                    FailureClass.VALIDATION_REJECTED,
                    "FANOUT_BUDGET_EXCEEDED",
                    fanout_count=self._policy.limits.maximum_fanout,
                )
            if total_attempts > self._policy.retry.maximum_attempts:
                return await self._dead_letter(
                    state,
                    FailureClass.RETRY_EXHAUSTED,
                    "SHARED_ATTEMPT_BUDGET_EXCEEDED",
                )
            if result.disposition is TaskDisposition.SUCCESS:
                return await self._transition(
                    state,
                    WorkflowState.SUCCEEDED,
                    "TASK_SUCCEEDED",
                    attempt_count=total_attempts,
                    fanout_count=total_fanout,
                    result_reference_sha256=result.result_reference_sha256,
                )
            if result.disposition is TaskDisposition.PARTIAL_EFFECT:
                compensating = await self._transition(
                    state,
                    WorkflowState.COMPENSATING,
                    "PARTIAL_EFFECT_COMPENSATION_REQUIRED",
                    failure_class=FailureClass.COMPENSATION_REQUIRED,
                    attempt_count=total_attempts,
                    fanout_count=total_fanout,
                    effect_reference_sha256=result.effect_reference_sha256,
                )
                if result.effect_reference_sha256 is None:
                    raise OrchestrationStateConflictError
                return await self._compensate(compensating, result.effect_reference_sha256)
            if result.disposition is TaskDisposition.OUTCOME_UNKNOWN:
                return await self._transition(
                    state,
                    WorkflowState.RECONCILIATION_REQUIRED,
                    "DEPENDENCY_OUTCOME_UNKNOWN",
                    failure_class=FailureClass.DEPENDENCY_OUTCOME_UNKNOWN,
                    attempt_count=total_attempts,
                    fanout_count=total_fanout,
                    resume_token_sha256=fingerprint(
                        {
                            "request_identity_sha256": state.request_identity_sha256,
                            "revision": state.revision + 1,
                            "workflow_id": state.workflow_id,
                        }
                    ),
                )
            if (
                result.disposition is TaskDisposition.RETRYABLE_FAILURE
                and total_attempts < self._policy.retry.maximum_attempts
            ):
                delay = delays[total_attempts - 1]
                state = await self._transition(
                    state,
                    WorkflowState.RETRY_WAIT,
                    result.safe_reason_code or "TRANSIENT_DEPENDENCY",
                    failure_class=result.failure_class,
                    attempt_count=total_attempts,
                    fanout_count=total_fanout,
                    next_retry_at=self._clock() + timedelta(seconds=delay),
                )
                await self._sleeper(float(delay))
                continue
            failure = (
                FailureClass.RETRY_EXHAUSTED
                if result.disposition is TaskDisposition.RETRYABLE_FAILURE
                else result.failure_class or FailureClass.PERMANENT_DEPENDENCY
            )
            return await self._dead_letter(
                state,
                failure,
                "RETRY_EXHAUSTED"
                if failure is FailureClass.RETRY_EXHAUSTED
                else result.safe_reason_code or "PERMANENT_DEPENDENCY",
                attempt_count=total_attempts,
                fanout_count=total_fanout,
            )
        return await self._dead_letter(
            state,
            FailureClass.RETRY_EXHAUSTED,
            "RETRY_EXHAUSTED",
        )

    async def _compensate(
        self, state: WorkflowExecutionState, effect_reference_sha256: str
    ) -> WorkflowExecutionState:
        result = await self._compensator.compensate(state, effect_reference_sha256)
        if result.succeeded:
            return await self._transition(
                state,
                WorkflowState.COMPENSATED,
                "COMPENSATION_SUCCEEDED",
                failure_class=FailureClass.COMPENSATION_REQUIRED,
                compensation_reference_sha256=result.compensation_reference_sha256,
            )
        return await self._dead_letter(
            state,
            FailureClass.COMPENSATION_FAILED,
            result.safe_reason_code or "COMPENSATION_FAILED",
        )

    async def _dead_letter(
        self,
        state: WorkflowExecutionState,
        failure_class: FailureClass,
        reason: str,
        **updates: object,
    ) -> WorkflowExecutionState:
        attempt_count = updates.get("attempt_count", state.attempt_count)
        if not isinstance(attempt_count, int):
            raise OrchestrationStateConflictError
        record = DeadLetterRecord(
            workflow_id=state.workflow_id,
            correlation_id=state.correlation_id,
            tenant_reference_sha256=state.tenant_reference_sha256,
            request_identity_sha256=state.request_identity_sha256,
            failure_class=failure_class,
            safe_reason_code=reason,
            attempt_count=attempt_count,
            state_revision=state.revision,
            recorded_at=self._clock(),
        )
        try:
            await self._dead_letter_sink.write(record)
        except Exception:
            return await self._transition(
                state,
                WorkflowState.RECONCILIATION_REQUIRED,
                "DEAD_LETTER_UNAVAILABLE",
                failure_class=FailureClass.DEAD_LETTER_UNAVAILABLE,
                resume_token_sha256=fingerprint(
                    {
                        "request_identity_sha256": state.request_identity_sha256,
                        "revision": state.revision + 1,
                        "workflow_id": state.workflow_id,
                    }
                ),
                **updates,
            )
        return await self._transition(
            state,
            WorkflowState.DEAD_LETTERED,
            reason,
            failure_class=failure_class,
            resume_token_sha256=None,
            **updates,
        )
