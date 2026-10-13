from __future__ import annotations

import asyncio

import pytest

from enterprise_ai_platform.orchestration.errors import (
    OrchestrationAuthorizationError,
    OrchestrationProviderError,
)
from enterprise_ai_platform.orchestration.models import ApprovalRequirement
from enterprise_ai_platform.orchestration.serialization import canonical_bytes
from enterprise_ai_platform.retrieval.models import Classification
from enterprise_ai_platform.serving.models import ArtifactApprovalState, ServingProvider
from tests.fakes.w8_003_orchestration import (
    make_auth,
    make_engine,
    make_event,
    make_harness,
    make_policy,
)


def test_cross_tenant_authorization_fails_before_state_or_provider_call() -> None:
    policy = make_policy()
    authorized = make_auth(tenant_id="tenant-a")
    attacker = make_auth(tenant_id="tenant-b", subject_id="subject-b")
    event = make_event(policy, authorized)
    harness = make_harness()

    with pytest.raises(OrchestrationAuthorizationError):
        asyncio.run(make_engine(policy, harness).submit(event, attacker))

    assert harness.states.states == {}
    assert harness.idempotency.bindings == {}
    assert harness.executor.calls == []


def test_insufficient_clearance_fails_before_state_creation() -> None:
    policy = make_policy()
    restricted = make_auth(clearance=Classification.RESTRICTED)
    event = make_event(
        policy,
        restricted,
        classification=Classification.CONFIDENTIAL,
        approval_requirement=ApprovalRequirement.SENSITIVE,
    )
    low_clearance = make_auth(clearance=Classification.INTERNAL)
    harness = make_harness()

    with pytest.raises(OrchestrationAuthorizationError):
        asyncio.run(make_engine(policy, harness).submit(event, low_clearance))

    assert harness.states.states == {}
    assert harness.executor.calls == []


def test_unapproved_artifact_and_substituted_provider_fail_before_idempotency() -> None:
    policy = make_policy()
    auth = make_auth()

    for event in (
        make_event(
            policy,
            auth,
            approval_state_artifact=ArtifactApprovalState.PENDING,
        ),
        make_event(policy, auth, requested_provider=ServingProvider.EKS),
    ):
        harness = make_harness()
        with pytest.raises(OrchestrationProviderError):
            asyncio.run(make_engine(policy, harness).submit(event, auth))
        assert harness.idempotency.bindings == {}
        assert harness.executor.calls == []


def test_audit_records_are_content_free_and_pseudonymous() -> None:
    policy = make_policy()
    auth = make_auth(tenant_id="tenant-secret", subject_id="subject-secret")
    harness = make_harness()
    asyncio.run(make_engine(policy, harness).submit(make_event(policy, auth), auth))

    serialized = b"".join(canonical_bytes(item) for item in harness.audit.transitions)
    assert b"tenant-secret" not in serialized
    assert b"subject-secret" not in serialized
    assert b"prompt" not in serialized.lower()
    assert b"document" not in serialized.lower()
