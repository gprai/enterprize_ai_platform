"""Unit coverage for W9-004 immutable evidence."""

from pydantic import ValidationError

from enterprise_ai_platform.model_supply_chain import (
    EligibilityStatus,
    EvidenceStatus,
    SupplyChainEligibility,
    fingerprint,
    load_supply_chain_policy,
    reconcile_candidate,
)
from tests.fakes.w9_004_model_supply_chain import NOW, make_eligibility


def test_eligibility_is_strict_immutable_and_stable() -> None:
    evidence = make_eligibility()
    assert fingerprint(evidence) == fingerprint(evidence.model_dump(mode="python"))
    assert evidence.deployment_approval == "NOT_AUTHORIZED"


def test_unknown_evidence_field_is_rejected() -> None:
    payload = make_eligibility().model_dump(mode="python")
    payload["unexpected"] = True
    try:
        SupplyChainEligibility.model_validate(payload, strict=True)
    except ValidationError:
        pass
    else:
        raise AssertionError("unknown evidence field was accepted")


def test_failed_license_and_opa_gate_cannot_be_reconciled_as_pass() -> None:
    passing = make_eligibility()
    failed = reconcile_candidate(
        candidate=passing.candidate,
        tenant_reference_sha256=passing.tenant_reference_sha256,
        classification=passing.classification,
        source_license=passing.source_license.model_copy(update={"status": EvidenceStatus.FAIL}),
        inventory=passing.inventory,
        scanners=passing.scanners,
        sboms=passing.sboms,
        provenance=passing.provenance,
        risk_treatments=passing.risk_treatments,
        opa_decision=passing.opa_decision.model_copy(update={"allow": False}),
        policy=load_supply_chain_policy(),
        generated_at=NOW,
    )
    assert failed.status is EligibilityStatus.FAIL
