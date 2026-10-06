import json
from pathlib import Path

import pytest
from tools.platformctl.live_validation import (
    W6004Error,
    canonical_evidence_sha256,
    validate_evidence_record,
    validate_residue,
)

from tests.fakes.w6_004_lifecycle import evidence_record

ROOT = Path(__file__).resolve().parents[2]

EXPECTED = [
    "final_evidence",
    "shared_external_service_linked_roles",
    "kms_keys_pending_deletion",
    "delayed_billing_records",
]


def test_only_approved_residual_classes_are_accepted() -> None:
    validate_residue(EXPECTED, EXPECTED)
    with pytest.raises(W6004Error, match="unexpected"):
        validate_residue(EXPECTED + ["eks_cluster"], EXPECTED)


def test_teardown_is_platform_first_and_bootstrap_last() -> None:
    value = json.loads((ROOT / "configs/lifecycle/w6-004.json").read_text(encoding="utf-8"))
    assert value["teardown"] == {
        "order": ["kubernetes", "platform", "versioned_state_objects", "bootstrap"],
        "remove_project_ecr_images": True,
        "remove_synthetic_s3_objects": True,
        "remove_opensearch_indexes": True,
        "shared_resources_excluded": True,
    }


@pytest.mark.parametrize(
    ("target", "scope"),
    [("platform", "platform-destroy"), ("bootstrap", "bootstrap-destroy")],
)
def test_destroy_evidence_binds_exact_target_and_scope(target: str, scope: str) -> None:
    value = evidence_record("w6-004.destroy.v1")
    value["target"] = target
    value["evidence_scope"] = scope
    value["output_root"] = (
        "E:/AI/.runtime/enterprise_ai_platform/w6-004/owner-test-01/"
        f"{scope}/{value['operation_id']}"
    )
    value["evidence_sha256"] = canonical_evidence_sha256(value)
    validate_evidence_record(value, expected_schema="w6-004.destroy.v1")


def test_destroy_evidence_rejects_target_scope_mismatch() -> None:
    value = evidence_record("w6-004.destroy.v1")
    value["target"] = "bootstrap"
    value["evidence_sha256"] = canonical_evidence_sha256(value)
    with pytest.raises(W6004Error, match="target and evidence scope"):
        validate_evidence_record(value, expected_schema="w6-004.destroy.v1")
