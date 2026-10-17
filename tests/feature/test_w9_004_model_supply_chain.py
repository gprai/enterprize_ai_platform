"""SUPPLY-002 and GHA-002 acceptance behavior."""

from enterprise_ai_platform.model_supply_chain import EligibilityStatus
from tests.fakes.w9_004_model_supply_chain import make_eligibility


def test_candidate_is_eligible_without_deployment_authority() -> None:
    evidence = make_eligibility()
    assert evidence.status is EligibilityStatus.PASS
    assert evidence.deployment_approval == "NOT_AUTHORIZED"
    assert evidence.classification.value == "INTERNAL"
