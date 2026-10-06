import pytest
from tools.platformctl.live_validation import (
    LIFECYCLE_ORDER,
    W6004Error,
    canonical_evidence_sha256,
    validate_evidence_record,
    validate_stage_sequence,
)

from tests.fakes.w6_004_lifecycle import evidence_record


def test_full_lifecycle_order_is_accepted() -> None:
    validate_stage_sequence(LIFECYCLE_ORDER)


def test_skipped_stage_is_rejected() -> None:
    with pytest.raises(W6004Error, match="incomplete"):
        validate_stage_sequence(LIFECYCLE_ORDER[:-1])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("coverage", "PARTIAL", "incomplete"),
        ("embedded_errors", ["pricing unavailable"], "embedded errors"),
        ("priced_resource_count", 0, "coverage"),
        ("estimated_usd", "2.01", "ceiling"),
    ],
)
def test_cost_gate_rejects_incomplete_or_over_cap_evidence(
    field: str,
    value: object,
    message: str,
) -> None:
    evidence = evidence_record("w6-004.cost.v1")
    evidence[field] = value
    evidence["evidence_sha256"] = canonical_evidence_sha256(evidence)
    with pytest.raises(W6004Error, match=message):
        validate_evidence_record(evidence, expected_schema="w6-004.cost.v1")


def test_live_test_schema_preserves_no_data_without_claiming_live_pass() -> None:
    evidence = evidence_record("w6-004.live-test.v1")
    evidence["status"] = "NOT RUN"
    evidence["slo_classification"] = "NO_DATA"
    evidence["evidence_sha256"] = canonical_evidence_sha256(evidence)
    assert (
        validate_evidence_record(evidence, expected_schema="w6-004.live-test.v1")["status"]
        == "NOT RUN"
    )
