import json
from pathlib import Path

from tools.platformctl.live_validation import (
    HISTORICAL_AUTHORIZATION_FAILURE,
    LIFECYCLE_ORDER,
    OWNER_SENTINEL,
    SCHEMA_FIELDS,
)

ROOT = Path(__file__).resolve().parents[2]


def test_w6_004_source_schema_and_sequence_are_closed() -> None:
    value = json.loads((ROOT / "configs/lifecycle/w6-004.json").read_text(encoding="utf-8"))
    assert tuple(value["lifecycle_order"]) == LIFECYCLE_ORDER
    assert set(value["owner_bindings"].values()) == {OWNER_SENTINEL}
    assert value["historical_authorization_failure"] == HISTORICAL_AUTHORIZATION_FAILURE


def test_no_executable_owner_values_are_checked_in() -> None:
    text = (ROOT / "configs/lifecycle/w6-004.json").read_text(encoding="utf-8")
    assert "finopsinfra" not in text
    assert "OWNER_BINDING_REQUIRED" in text


def test_complete_lifecycle_schema_inventory_is_closed() -> None:
    assert set(SCHEMA_FIELDS) == {
        "w6-004.discovery.v1",
        "w6-004.inputs.v1",
        "w6-004.plan.v1",
        "w6-004.normalized-plan.v1",
        "w6-004.opa.v1",
        "w6-004.cost.v1",
        "w6-004.approval.v1",
        "w6-004.apply.v1",
        "w6-004.partial-apply.v1",
        "w6-004.image.v1",
        "w6-004.vulnerability-scan.v1",
        "w6-004.sbom.v1",
        "w6-004.provenance.v1",
        "w6-004.release-binding.v1",
        "w6-004.deployment.v1",
        "w6-004.live-test.v1",
        "w6-004.application-rollback.v1",
        "w6-004.infrastructure-rollback.v1",
        "w6-004.destroy.v1",
        "w6-004.residue.v1",
        "w6-004.billing.v1",
        "w6-004.closure.v1",
    }


def test_provider_computed_shape_fixture_has_only_approved_unknown_paths() -> None:
    value = json.loads(
        (ROOT / "tests/fixtures/w6_004/provider-computed-shapes.json").read_text(encoding="utf-8")
    )
    assert value == {
        "schema_version": "w6-004.provider-computed-shapes.v1",
        "allowed_unknown_paths": [
            "module.eks.aws_eks_cluster.this.endpoint",
            "module.eks.aws_eks_cluster.this.certificate_authority",
            "module.eks.aws_eks_node_group.application.resources",
        ],
    }


def test_partial_apply_fixture_freezes_mutation_for_read_only_reconciliation() -> None:
    value = json.loads(
        (ROOT / "tests/fixtures/w6_004/partial-apply-inventory.json").read_text(encoding="utf-8")
    )
    assert value["schema_version"] == "w6-004.partial-apply-inventory.v1"
    assert value["mutation_frozen"] is True
    assert value["next_action"] == "READ_ONLY_RECONCILIATION_REQUIRED"
    assert value["resources"] == [
        {
            "address": "module.eks.aws_eks_cluster.this",
            "native_status": "ACTIVE",
            "state_status": "MISSING",
        }
    ]


def test_native_inventory_fixture_preserves_kms_and_billing_uncertainty() -> None:
    value = json.loads(
        (ROOT / "tests/fixtures/w6_004/native-resource-inventory.json").read_text(encoding="utf-8")
    )
    assert value == {
        "schema_version": "w6-004.native-resource-inventory.v1",
        "classification": "fixture-only",
        "account_id": "526338061652",
        "region": "ap-southeast-1",
        "resources": [],
        "kms_pending_deletion": [],
        "billing_records_delayed": True,
    }
