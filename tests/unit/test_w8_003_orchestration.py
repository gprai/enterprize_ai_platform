from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.orchestration.errors import (
    OrchestrationIdempotencyError,
    OrchestrationQuotaError,
)
from enterprise_ai_platform.orchestration.models import (
    FailureClass,
    TaskDisposition,
    TaskResult,
    WorkflowState,
)
from tests.fakes.w8_003_orchestration import (
    InMemoryQuotaGate,
    make_auth,
    make_engine,
    make_event,
    make_harness,
    make_policy,
    transient_failure,
)


def test_per_tenant_active_quota_is_enforced_and_released() -> None:
    async def exercise() -> None:
        gate = InMemoryQuotaGate()
        first = await gate.reserve("a" * 64)
        second = await gate.reserve("a" * 64)
        with pytest.raises(OrchestrationQuotaError):
            await gate.reserve("a" * 64)
        third_tenant = await gate.reserve("b" * 64)
        assert gate.active_global == 3
        assert gate.active_by_tenant == {"a" * 64: 2, "b" * 64: 1}
        await first.release()
        await second.release()
        await third_tenant.release()
        assert gate.active_global == 0
        assert gate.active_by_tenant == {}

    asyncio.run(exercise())


def test_successful_workflow_is_terminal_audited_and_quota_clean() -> None:
    policy = make_policy()
    auth = make_auth()
    event = make_event(policy, auth)
    harness = make_harness()

    state = asyncio.run(make_engine(policy, harness).submit(event, auth))

    assert state.state is WorkflowState.SUCCEEDED
    assert state.result_reference_sha256 == "e" * 64
    assert [item.next_state for item in harness.audit.transitions] == [
        WorkflowState.RECEIVED,
        WorkflowState.AUTHORIZED,
        WorkflowState.IDEMPOTENCY_RESERVED,
        WorkflowState.QUOTA_RESERVED,
        WorkflowState.READY,
        WorkflowState.RUNNING,
        WorkflowState.SUCCEEDED,
    ]
    assert harness.quota.active_global == 0
    assert harness.quota.active_by_tenant == {}


def test_retry_schedule_is_exponential_and_bounded() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [
        transient_failure(),
        transient_failure(),
        TaskResult(
            disposition=TaskDisposition.SUCCESS,
            result_reference_sha256="7" * 64,
        ),
    ]

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.SUCCEEDED
    assert state.attempt_count == 3
    assert harness.clock.sleeps == [1.0, 2.0]
    assert len(harness.executor.calls) == 3


def test_exact_redelivery_returns_prior_terminal_state_without_dispatch() -> None:
    policy = make_policy()
    auth = make_auth()
    event = make_event(policy, auth)
    harness = make_harness()
    engine = make_engine(policy, harness)

    first = asyncio.run(engine.submit(event, auth))
    second = asyncio.run(engine.submit(event, auth))

    assert second == first
    assert len(harness.executor.calls) == 1


def test_idempotency_key_reuse_with_modified_request_fails_closed() -> None:
    policy = make_policy()
    auth = make_auth()
    event = make_event(policy, auth)
    harness = make_harness()
    engine = make_engine(policy, harness)
    asyncio.run(engine.submit(event, auth))
    modified_detail = event.detail.model_copy(update={"input_reference_sha256": "6" * 64})
    modified = event.model_copy(update={"detail": modified_detail})

    with pytest.raises(OrchestrationIdempotencyError):
        asyncio.run(engine.submit(modified, auth))

    assert len(harness.executor.calls) == 1


def test_shared_attempt_budget_cannot_be_hidden_by_an_adapter() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [
        TaskResult(
            disposition=TaskDisposition.RETRYABLE_FAILURE,
            attempts_consumed=3,
            failure_class=FailureClass.TRANSIENT_DEPENDENCY,
            safe_reason_code="TRANSIENT_DEPENDENCY",
        )
    ]

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.DEAD_LETTERED
    assert state.failure_class is FailureClass.RETRY_EXHAUSTED
    assert len(harness.executor.calls) == 1
    assert len(harness.dead_letter.records) == 1


def test_tenant_quota_denial_is_terminal_and_releases_no_task() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.quota.maximum_global = 0

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.DENIED
    assert state.failure_class is FailureClass.TENANT_QUOTA_EXCEEDED
    assert harness.executor.calls == []


def test_cumulative_fanout_cannot_exceed_eight() -> None:
    policy = make_policy()
    auth = make_auth()
    harness = make_harness()
    harness.executor.results = [
        TaskResult(
            disposition=TaskDisposition.RETRYABLE_FAILURE,
            fanout_consumed=8,
            failure_class=FailureClass.TRANSIENT_DEPENDENCY,
            safe_reason_code="TRANSIENT_DEPENDENCY",
        ),
        TaskResult(
            disposition=TaskDisposition.SUCCESS,
            fanout_consumed=1,
            result_reference_sha256="5" * 64,
        ),
    ]

    state = asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    assert state.state is WorkflowState.DEAD_LETTERED
    assert state.failure_class is FailureClass.VALIDATION_REJECTED
    assert state.fanout_count == 8
