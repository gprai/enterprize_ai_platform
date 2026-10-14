"""Security and privacy checks for W9-001 training."""

from copy import deepcopy
from pathlib import Path

import pytest

from enterprise_ai_platform.training import (
    Hyperparameter,
    OfflineSageMakerProvider,
    TenantTrainingAuthorizer,
    TrainingAdmissionError,
    TrainingAuthorizationError,
    TrainingService,
    TrainingValidationError,
    load_training_policy,
)
from tests.fakes.w9_001_training import (
    NOW,
    FakeTorchRuntime,
    make_approval,
    make_auth,
    make_request,
)


def test_cross_tenant_request_fails_before_provider_preparation() -> None:
    owner = make_auth()
    other = make_auth(tenant_id="tenant-b")
    request = make_request(auth=owner)
    service = TrainingService(
        policy=load_training_policy(),
        runtime=FakeTorchRuntime(),
        authorizer=TenantTrainingAuthorizer(),
        provider=OfflineSageMakerProvider(),
    )

    with pytest.raises(TrainingAuthorizationError, match="tenant"):
        service.prepare(request, make_approval(request), other, now=NOW)


def test_secret_named_hyperparameters_are_rejected() -> None:
    for key in ("api_key", "password", "access_token", "client_secret"):
        with pytest.raises(ValueError, match="secret-bearing"):
            Hyperparameter(key=key, value="must-not-be-recorded")


def test_policy_substitution_is_rejected_before_provider_preparation() -> None:
    request = make_request()
    payload = deepcopy(request.model_dump(mode="python"))
    payload["policy_sha256"] = "0" * 64
    substituted = type(request).model_validate(payload, strict=True)
    service = TrainingService(
        policy=load_training_policy(),
        runtime=FakeTorchRuntime(),
        authorizer=TenantTrainingAuthorizer(),
        provider=OfflineSageMakerProvider(),
    )

    with pytest.raises(TrainingValidationError, match="policy"):
        service.prepare(substituted, make_approval(substituted), make_auth(), now=NOW)


def test_post_approval_input_substitution_is_rejected() -> None:
    request = make_request()
    approval = make_approval(request)
    payload = deepcopy(request.model_dump(mode="python"))
    payload["code"]["source_sha256"] = "0" * 64
    substituted = type(request).model_validate(payload, strict=True)
    service = TrainingService(
        policy=load_training_policy(),
        runtime=FakeTorchRuntime(),
        authorizer=TenantTrainingAuthorizer(),
        provider=OfflineSageMakerProvider(),
    )

    with pytest.raises(TrainingAdmissionError, match="approval"):
        service.prepare(substituted, approval, make_auth(), now=NOW)


def test_post_approval_budget_substitution_is_rejected() -> None:
    request = make_request()
    approval = make_approval(request)
    payload = deepcopy(request.model_dump(mode="python"))
    payload["budget_reference_sha256"] = "0" * 64
    substituted = type(request).model_validate(payload, strict=True)
    service = TrainingService(
        policy=load_training_policy(),
        runtime=FakeTorchRuntime(),
        authorizer=TenantTrainingAuthorizer(),
        provider=OfflineSageMakerProvider(),
    )

    with pytest.raises(TrainingAdmissionError, match="approval"):
        service.prepare(substituted, approval, make_auth(), now=NOW)


def test_duplicate_policy_keys_and_yaml_aliases_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "schema_version: w9-001.governed-training-policy.v1\nschema_version: duplicate\n",
        encoding="utf-8",
    )
    alias = tmp_path / "alias.yaml"
    alias.write_text("value: &shared one\ncopy: *shared\n", encoding="utf-8")

    with pytest.raises(TrainingValidationError, match="duplicate YAML key"):
        load_training_policy(duplicate)
    with pytest.raises(TrainingValidationError, match="aliases"):
        load_training_policy(alias)
