"""Security tests for separation of duties and fail-closed registry admission."""

from pathlib import Path

import pytest

from enterprise_ai_platform.agent.serialization import hash_identifier
from enterprise_ai_platform.model_registry import (
    ModelPackageManifest,
    PackageApproval,
    PromotionRequest,
    PromotionStage,
)
from tests.fakes.w9_003_model_registry import (
    NOW,
    make_auth,
    make_package,
    make_package_approval,
    make_service,
)


def test_registrant_cannot_self_approve() -> None:
    admin = make_auth()
    service, _ = make_service()
    record = service.register(make_package(auth=admin), admin, now=NOW)
    approval = make_package_approval(record).model_dump(mode="python")
    approval["approver_reference_sha256"] = hash_identifier(admin.subject_id)

    with pytest.raises(ValueError, match="own package"):
        PackageApproval.model_validate(approval, strict=True)


def test_lineage_substitution_and_stage_skip_fail_closed() -> None:
    package = make_package()
    payload = package.model_dump(mode="python")
    payload["lineage_export_identity_sha256"] = "0" * 64
    payload["experiment_run_identity_sha256"] = "1" * 64
    with pytest.raises(ValueError, match="experiment run identity"):
        ModelPackageManifest.model_validate(payload, strict=True)

    record_payload = {
        "request_id": "00000000-0000-4000-8003-000000000001",
        "idempotency_key": "a" * 64,
        "tenant_reference_sha256": package.tenant_reference_sha256,
        "executor_reference_sha256": package.registrant_reference_sha256,
        "authorization_reference_sha256": package.authorization_reference_sha256,
        "package_identity_sha256": "b" * 64,
        "package_approval_identity_sha256": "c" * 64,
        "source_stage": PromotionStage.CANDIDATE,
        "target_stage": PromotionStage.PRODUCTION,
        "policy_sha256": package.policy_sha256,
        "requested_at": NOW,
        "deadline_at": package.deadline_at,
    }
    with pytest.raises(ValueError, match="exactly one"):
        PromotionRequest.model_validate(record_payload, strict=True)


def test_implementation_has_no_sdk_network_or_credential_access() -> None:
    source_root = Path(__file__).resolve().parents[2] / "src/enterprise_ai_platform/model_registry"
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(source_root.glob("*.py"))
    ).casefold()

    for forbidden in (
        "import boto3",
        "import requests",
        "import socket",
        "os.environ",
        "subprocess",
        "aws_secret_access_key",
    ):
        assert forbidden not in combined
