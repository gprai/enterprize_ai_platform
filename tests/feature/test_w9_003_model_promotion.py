"""Feature flow for governed model-package promotion and exact rollback."""

from enterprise_ai_platform.model_registry import ApprovalState, PromotionStage
from enterprise_ai_platform.retrieval.models import Role
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


def test_reviewed_lineage_promotes_in_order_and_rolls_back_to_known_good() -> None:
    admin = make_auth()
    reviewer = make_auth(role=Role.REVIEWER, subject_id="registry-reviewer-a")
    service, store = make_service()

    first = service.register(make_package(auth=admin), admin, now=NOW)
    first = service.review(
        first.package.package_id,
        make_package_approval(first, reviewer=reviewer),
        reviewer,
        now=NOW,
    )
    first_staging = make_promotion_request(first, auth=admin, request_number=1)
    service.promote(
        first_staging,
        make_promotion_approval(first_staging, reviewer=reviewer),
        admin,
        now=NOW,
    )
    first_production = make_promotion_request(
        first,
        auth=admin,
        request_number=2,
        source_stage=PromotionStage.STAGING,
        target_stage=PromotionStage.PRODUCTION,
    )
    first_result = service.promote(
        first_production,
        make_promotion_approval(first_production, reviewer=reviewer),
        admin,
        now=NOW,
    )
    known_good = make_known_good(
        first_result,
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
    service.promote(
        second_staging,
        make_promotion_approval(second_staging, reviewer=reviewer),
        admin,
        now=NOW,
    )
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
        make_promotion_approval(second_production, reviewer=reviewer),
        admin,
        now=NOW,
    )

    rollback = make_rollback_request(current=second, known_good=known_good, auth=admin)
    restored = service.rollback(
        rollback,
        make_rollback_approval(rollback, reviewer=reviewer),
        admin,
        now=NOW,
    )

    assert restored.restored_package_sha256 == first.package_identity_sha256
    assert restored.failed_package_sha256 == second.package_identity_sha256
    assert restored.failed_candidate_preserved is True
    assert restored.deployment_approval == "NOT_AUTHORIZED"
    assert store.current(PromotionStage.PRODUCTION) == first.package_identity_sha256
    assert store.current(PromotionStage.STAGING) == second.package_identity_sha256
    assert store.get(second.package.package_id).approval_state is ApprovalState.APPROVED
