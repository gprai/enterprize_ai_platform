from __future__ import annotations

import asyncio

import pytest
from tests.fakes.w8_003_orchestration import (
    make_auth,
    make_engine,
    make_event,
    make_harness,
    make_policy,
    permanent_failure,
)

from enterprise_ai_platform.orchestration.errors import OrchestrationValidationError
from enterprise_ai_platform.orchestration.models import (
    FailureClass,
    ResumeAction,
    TaskDisposition,
    TaskResult,
    WorkflowState,
)


def test_withdraw_admission_stops_new_work_without_dispatch() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    engine = make_engine(policy, harness)
    engine.withdraw_admission()

    with pytest.raises(OrchestrationValidationError):
        asyncio.run(engine.submit(make_event(policy, auth), auth))

    assert harness.executor.calls == []
    assert harness.states.states == {}


def test_permanent_failure_dead_letters_exact_work() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [permanent_failure()]

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.DEAD_LETTERED
    assert len(harness.dead_letter.records) == 1
    assert harness.dead_letter.records[0].workflow_id == state.workflow_id


def test_failed_dead_letter_requires_bound_resume_decision() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [permanent_failure()]
    harness.dead_letter.fail = True
    engine = make_engine(policy, harness)

    pending = asyncio.run(engine.submit(make_event(policy, auth), auth))

    assert pending.state is WorkflowState.RECONCILIATION_REQUIRED
    assert pending.failure_class is FailureClass.DEAD_LETTER_UNAVAILABLE
    assert pending.resume_token_sha256 is not None
    harness.dead_letter.fail = False
    completed = asyncio.run(
        engine.resume(
            workflow_id=pending.workflow_id,
            expected_revision=pending.revision,
            resume_token_sha256=pending.resume_token_sha256,
            action=ResumeAction.DEAD_LETTER,
            auth_context=auth,
        )
    )
    assert completed.state is WorkflowState.DEAD_LETTERED
    assert len(harness.dead_letter.records) == 1
    replayed = asyncio.run(engine.submit(make_event(policy, auth), auth))
    assert replayed == completed
    assert len(harness.dead_letter.records) == 1


def test_unknown_outcome_does_not_retry_automatically() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [
        TaskResult(
            disposition=TaskDisposition.OUTCOME_UNKNOWN,
            failure_class=FailureClass.DEPENDENCY_OUTCOME_UNKNOWN,
            safe_reason_code="DEPENDENCY_OUTCOME_UNKNOWN",
        )
    ]

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.RECONCILIATION_REQUIRED
    assert state.resume_token_sha256 is not None
    assert len(harness.executor.calls) == 1


def test_owner_cancellation_is_terminal_and_idempotent() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [
        TaskResult(
            disposition=TaskDisposition.OUTCOME_UNKNOWN,
            failure_class=FailureClass.DEPENDENCY_OUTCOME_UNKNOWN,
            safe_reason_code="DEPENDENCY_OUTCOME_UNKNOWN",
        )
    ]
    engine = make_engine(policy, harness)
    pending = asyncio.run(engine.submit(make_event(policy, auth), auth))

    cancelled = asyncio.run(engine.cancel(pending.workflow_id, auth))
    repeated = asyncio.run(engine.cancel(pending.workflow_id, auth))

    assert cancelled.state is WorkflowState.CANCELLED
    assert repeated == cancelled
    assert len(harness.executor.calls) == 1
