"""Composition tests for authorization, idempotency, promotion, and cancellation."""

import pytest

from enterprise_ai_platform.model_registry import (
    PromotionStage,
    RegistryAdmissionError,
    RegistryAuthorizationError,
    RegistryStateError,
)
from enterprise_ai_platform.retrieval.models import Role
from tests.fakes.w9_003_model_registry import (
    NOW,
    make_auth,
    make_package,
    make_package_approval,
    make_promotion_approval,
    make_promotion_request,
    make_service,
)


def test_exact_reviewed_package_promotes_one_stage_without_deployment_authority() -> None:
    admin = make_auth()
    reviewer = make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    service, store = make_service()
    record = service.register(make_package(auth=admin), admin, now=NOW)
    record = service.review(
        record.package.package_id,
        make_package_approval(record, reviewer=reviewer),
        reviewer,
        now=NOW,
    )
    request = make_promotion_request(record, auth=admin)
    result = service.promote(
        request,
        make_promotion_approval(request, reviewer=reviewer),
        admin,
        now=NOW,
    )

    assert result.status == "PROMOTED"
    assert result.deployment_approval == "NOT_AUTHORIZED"
    assert store.current(PromotionStage.STAGING) == record.package_identity_sha256
    assert store.current(PromotionStage.PRODUCTION) is None


def test_identical_registration_replays_and_conflicting_key_fails() -> None:
    admin = make_auth()
    service, _ = make_service()
    package = make_package(auth=admin)

    assert service.register(package, admin, now=NOW) == service.register(package, admin, now=NOW)
    conflicting = make_package(
        auth=admin,
        package_number=2,
        artifact_character="e",
        idempotency_key=package.idempotency_key,
    )
    with pytest.raises(RegistryAdmissionError, match="idempotency"):
        service.register(conflicting, admin, now=NOW)


def test_cross_tenant_fails_before_registration() -> None:
    admin = make_auth()
    wrong_tenant = make_auth(tenant_id="tenant-b")
    service, store = make_service()

    with pytest.raises(RegistryAuthorizationError, match="tenant"):
        service.register(make_package(auth=admin), wrong_tenant, now=NOW)
    assert store.list() == ()


def test_cancelled_promotion_cannot_apply_and_applied_promotion_cannot_cancel() -> None:
    admin = make_auth()
    reviewer = make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    service, _ = make_service()
    first = service.register(make_package(auth=admin), admin, now=NOW)
    first = service.review(
        first.package.package_id,
        make_package_approval(first, reviewer=reviewer),
        reviewer,
        now=NOW,
    )
    cancelled = make_promotion_request(first, auth=admin)
    service.cancel(cancelled, admin, now=NOW)
    with pytest.raises(RegistryStateError, match="cancelled"):
        service.promote(
            cancelled,
            make_promotion_approval(cancelled, reviewer=reviewer),
            admin,
            now=NOW,
        )

    second = service.register(
        make_package(auth=admin, package_number=2, artifact_character="e"), admin, now=NOW
    )
    second = service.review(
        second.package.package_id,
        make_package_approval(second, reviewer=reviewer),
        reviewer,
        now=NOW,
    )
    applied = make_promotion_request(second, auth=admin, request_number=2)
    service.promote(applied, make_promotion_approval(applied, reviewer=reviewer), admin, now=NOW)
    with pytest.raises(RegistryStateError, match="rollback"):
        service.cancel(applied, admin, now=NOW)
