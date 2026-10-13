from __future__ import annotations

import asyncio
from datetime import timedelta

from enterprise_ai_platform.orchestration.models import (
    ApprovalRequirement,
    ApprovalStatus,
    CostClass,
    FailureClass,
    TaskDisposition,
    TaskResult,
    WorkflowKind,
    WorkflowState,
)
from tests.fakes.w8_003_orchestration import (
    make_auth,
    make_engine,
    make_event,
    make_harness,
    make_policy,
    transient_failure,
)


def test_exhausted_retries_route_once_to_dead_letter() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [transient_failure(), transient_failure(), transient_failure()]

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.DEAD_LETTERED
    assert state.failure_class is FailureClass.RETRY_EXHAUSTED
    assert harness.clock.sleeps == [1.0, 2.0]
    assert len(harness.dead_letter.records) == 1


def test_approval_denial_is_terminal_and_never_dispatches() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.approval.status = ApprovalStatus.DENIED
    event = make_event(
        policy,
        auth,
        approval_requirement=ApprovalRequirement.HIGH_COST,
        cost_class=CostClass.HIGH,
    )

    state = asyncio.run(make_engine(policy, harness).submit(event, auth))

    assert state.state is WorkflowState.DENIED
    assert state.failure_class is FailureClass.APPROVAL_DENIED
    assert harness.executor.calls == []


def test_expired_approval_is_classified_without_dispatch() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.approval.status = ApprovalStatus.EXPIRED
    event = make_event(
        policy,
        auth,
        approval_requirement=ApprovalRequirement.SENSITIVE,
    )

    state = asyncio.run(make_engine(policy, harness).submit(event, auth))

    assert state.state is WorkflowState.DENIED
    assert state.failure_class is FailureClass.APPROVAL_EXPIRED
    assert harness.executor.calls == []


def test_partial_effect_is_compensated_once() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [
        TaskResult(
            disposition=TaskDisposition.PARTIAL_EFFECT,
            effect_reference_sha256="4" * 64,
            failure_class=FailureClass.COMPENSATION_REQUIRED,
            safe_reason_code="PARTIAL_EFFECT",
        )
    ]

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.COMPENSATED
    assert state.compensation_reference_sha256 == "f" * 64
    assert len(harness.compensator.calls) == 1
    assert harness.dead_letter.records == []


def test_workflow_deadline_stops_retry_before_duplicate_dispatch() -> None:
    policy = make_policy()
    auth = make_auth()
    event = make_event(policy, auth)
    harness = make_harness()
    harness.clock.current = event.detail.deadline_at - timedelta(milliseconds=500)
    harness.executor.results = [transient_failure()]

    state = asyncio.run(make_engine(policy, harness).submit(event, auth))

    assert state.state is WorkflowState.TIMED_OUT
    assert state.failure_class is FailureClass.WORKFLOW_TIMEOUT
    assert len(harness.executor.calls) == 1


def test_training_always_requires_approval_and_uses_no_unapproved_fallback() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    event = make_event(policy, auth, kind=WorkflowKind.MODEL_TRAINING)

    state = asyncio.run(make_engine(policy, harness).submit(event, auth))

    assert state.state is WorkflowState.SUCCEEDED
    assert harness.approval.calls == 1
    assert len(harness.executor.calls) == 1
