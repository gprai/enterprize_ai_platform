import pytest
from tests.fakes.w6_004_lifecycle import evidence_record
from tools.platformctl.live_validation import (
    LIFECYCLE_ORDER,
    W6004Error,
    canonical_evidence_sha256,
    validate_evidence_record,
)


def test_rollback_precedes_teardown_and_residue_verification() -> None:
    assert LIFECYCLE_ORDER.index("application_rollback") < LIFECYCLE_ORDER.index(
        "infrastructure_rollback"
    )
    assert LIFECYCLE_ORDER.index("infrastructure_rollback") < LIFECYCLE_ORDER.index(
        "complete_teardown"
    )
    assert LIFECYCLE_ORDER[-1] == "residue_cost_verification"


def test_application_rollback_requires_distinct_regression_and_restored_digest() -> None:
    value = evidence_record("w6-004.application-rollback.v1")
    validate_evidence_record(value, expected_schema="w6-004.application-rollback.v1")

    value["regression_digest"] = value["known_good_digest"]
    value["evidence_sha256"] = canonical_evidence_sha256(value)
    with pytest.raises(W6004Error, match="application rollback identity"):
        validate_evidence_record(value, expected_schema="w6-004.application-rollback.v1")


def test_infrastructure_rollback_requires_distinct_plan_and_restored_state() -> None:
    value = evidence_record("w6-004.infrastructure-rollback.v1")
    validate_evidence_record(value, expected_schema="w6-004.infrastructure-rollback.v1")

    value["restore_plan_sha256"] = value["regression_plan_sha256"]
    value["evidence_sha256"] = canonical_evidence_sha256(value)
    with pytest.raises(W6004Error, match="infrastructure rollback identity"):
        validate_evidence_record(value, expected_schema="w6-004.infrastructure-rollback.v1")
