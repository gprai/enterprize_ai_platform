"""Composition checks for authorization through offline provider preparation."""

from enterprise_ai_platform.training import (
    OfflineSageMakerProvider,
    TenantTrainingAuthorizer,
    TrainingOutcome,
    TrainingService,
    load_training_policy,
)
from tests.fakes.w9_001_training import (
    NOW,
    FakeTorchRuntime,
    make_approval,
    make_auth,
    make_request,
)


def test_authorized_request_reaches_only_the_offline_provider() -> None:
    auth = make_auth()
    request = make_request(auth=auth)
    service = TrainingService(
        policy=load_training_policy(),
        runtime=FakeTorchRuntime(),
        authorizer=TenantTrainingAuthorizer(),
        provider=OfflineSageMakerProvider(),
    )

    result = service.prepare(request, make_approval(request), auth, now=NOW)

    assert result.outcome is TrainingOutcome.CANDIDATE_READY
    assert result.live_execution == "NOT_AUTHORIZED"
    assert result.candidate_artifact_sha256 is not None


def test_idempotent_replay_returns_the_same_candidate_identity() -> None:
    auth = make_auth()
    request = make_request(auth=auth)
    service = TrainingService(
        policy=load_training_policy(),
        runtime=FakeTorchRuntime(),
        authorizer=TenantTrainingAuthorizer(),
        provider=OfflineSageMakerProvider(),
    )
    approval = make_approval(request)

    first = service.prepare(request, approval, auth, now=NOW)
    second = service.prepare(request, approval, auth, now=NOW)

    assert first == second
