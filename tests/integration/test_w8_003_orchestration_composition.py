from __future__ import annotations

import asyncio

from enterprise_ai_platform.orchestration.models import (
    ApprovalRequirement,
    WorkflowKind,
    WorkflowState,
)
from enterprise_ai_platform.retrieval.models import Classification
from enterprise_ai_platform.serving.models import ServingProvider
from tests.fakes.w8_003_orchestration import (
    make_auth,
    make_engine,
    make_event,
    make_harness,
    make_policy,
)


def test_all_three_workflow_kinds_use_one_bounded_engine() -> None:
    policy = make_policy()
    scenarios = (
        (
            WorkflowKind.ASYNCHRONOUS_INFERENCE,
            ApprovalRequirement.NONE,
            ServingProvider.BEDROCK,
        ),
        (WorkflowKind.LONG_RUNNING_INGESTION, ApprovalRequirement.NONE, None),
        (WorkflowKind.MODEL_TRAINING, ApprovalRequirement.TRAINING, None),
    )

    for kind, approval, expected_provider in scenarios:
        auth = make_auth()
        harness = make_harness()
        event = make_event(policy, auth, kind=kind, approval_requirement=approval)
        state = asyncio.run(make_engine(policy, harness).submit(event, auth))

        assert state.state is WorkflowState.SUCCEEDED
        if kind is WorkflowKind.MODEL_TRAINING:
            assert state.provider is None
            assert state.artifact_identity_sha256 is None
            assert state.training_request_identity_sha256 == "7" * 64
            assert harness.approval.calls == 1
        else:
            assert state.provider is expected_provider


def test_long_running_ingestion_preserves_w7_classification_boundary() -> None:
    policy = make_policy()
    auth = make_auth()

    try:
        make_event(
            policy,
            auth,
            kind=WorkflowKind.LONG_RUNNING_INGESTION,
            classification=Classification.CONFIDENTIAL,
            approval_requirement=ApprovalRequirement.SENSITIVE,
        )
    except ValueError as exc:
        assert "PUBLIC and INTERNAL" in str(exc)
    else:
        raise AssertionError("unsupported W7 ingestion classification was accepted")


def test_correlation_and_tenant_references_survive_every_transition() -> None:
    policy = make_policy()
    auth = make_auth()
    event = make_event(policy, auth)
    harness = make_harness()

    asyncio.run(make_engine(policy, harness).submit(event, auth))

    assert {item.correlation_id for item in harness.audit.transitions} == {
        event.detail.correlation_id
    }
    assert {item.tenant_reference_sha256 for item in harness.audit.transitions} == {
        event.detail.tenant_reference_sha256
    }
    assert all(item.transition_sha256 for item in harness.audit.transitions)
