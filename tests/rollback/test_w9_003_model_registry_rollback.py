"""Rollback tests for exact known-good identity restoration."""

import pytest
from tests.fakes.w9_003_model_registry import (
    NOW,
    make_auth,
    make_known_good,
    make_package,
    make_package_approval,
    make_promotion_approval,
    make_promotion_request,
    make_rollback_approval,
    make_rollback_request,
    make_service,
)

from enterprise_ai_platform.model_registry import PromotionStage, RegistryValidationError
from enterprise_ai_platform.retrieval.models import Role


def test_substituted_known_good_reference_is_rejected() -> None:
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
    staging = make_promotion_request(first, auth=admin, request_number=1)
    service.promote(staging, make_promotion_approval(staging), admin, now=NOW)
    production = make_promotion_request(
        first,
        auth=admin,
        request_number=2,
        source_stage=PromotionStage.STAGING,
        target_stage=PromotionStage.PRODUCTION,
    )
    promoted = service.promote(
        production,
        make_promotion_approval(production),
        admin,
        now=NOW,
    )
    known_good = make_known_good(
        promoted,
        tenant_reference_sha256=first.package.tenant_reference_sha256,
        reviewer=reviewer,
    )
    service.record_known_good(known_good, reviewer, now=NOW)

    second = service.register(
        make_package(auth=admin, package_number=2, artifact_character="e"),
        admin,
        now=NOW,
    )
    second = service.review(
        second.package.package_id,
        make_package_approval(second, reviewer=reviewer),
        reviewer,
        now=NOW,
    )
    second_staging = make_promotion_request(
        second,
        auth=admin,
        request_number=3,
        expected_target=first.package_identity_sha256,
    )
    service.promote(second_staging, make_promotion_approval(second_staging), admin, now=NOW)
    second_production = make_promotion_request(
        second,
        auth=admin,
        request_number=4,
        source_stage=PromotionStage.STAGING,
        target_stage=PromotionStage.PRODUCTION,
        expected_target=first.package_identity_sha256,
    )
    service.promote(
        second_production,
        make_promotion_approval(second_production),
        admin,
        now=NOW,
    )
    rollback = make_rollback_request(current=second, known_good=known_good, auth=admin)
    substituted = rollback.model_copy(update={"known_good_reference_sha256": "0" * 64})

    with pytest.raises(RegistryValidationError, match="known-good reference"):
        service.rollback(
            substituted,
            make_rollback_approval(substituted),
            admin,
            now=NOW,
        )
