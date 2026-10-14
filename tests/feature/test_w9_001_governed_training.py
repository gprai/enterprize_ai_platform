"""Business behavior for governed, cost-gated offline training."""

import pytest

from enterprise_ai_platform.training import (
    OfflineSageMakerProvider,
    PeftRequest,
    TenantTrainingAuthorizer,
    TrainingAdmissionError,
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


def test_peft_is_disabled_by_default_and_requires_explicit_approval() -> None:
    auth = make_auth()
    request = make_request(
        auth=auth,
        peft=PeftRequest(enabled=True, method="lora", rank=8, target_modules=("q_proj",)),
    )
    service = TrainingService(
        policy=load_training_policy(),
        runtime=FakeTorchRuntime(),
        authorizer=TenantTrainingAuthorizer(),
        provider=OfflineSageMakerProvider(),
    )

    with pytest.raises(TrainingAdmissionError, match="PEFT"):
        service.prepare(request, make_approval(request), auth, now=NOW)

    result = service.prepare(
        request,
        make_approval(request, peft_approved=True),
        auth,
        now=NOW,
    )
    assert result.candidate_artifact_sha256 is not None


def test_candidate_specification_does_not_claim_model_approval() -> None:
    request = make_request()
    rendered = request.model_dump_json()

    assert "APPROVED_MODEL" not in rendered
    assert request.resources.instance_count == 1
    assert request.resources.runtime_seconds <= 21600
