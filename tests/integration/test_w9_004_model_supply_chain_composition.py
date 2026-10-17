"""Local W9-004 composition checks."""

from enterprise_ai_platform.model_supply_chain import require_registry_eligible
from tests.fakes.w9_004_model_supply_chain import NOW, make_eligibility


def test_pass_evidence_composes_with_registry_admission() -> None:
    evidence = make_eligibility()
    candidate = evidence.candidate
    require_registry_eligible(
        evidence,
        artifact_source_uri=candidate.artifact_source_uri,
        artifact_sha256=candidate.artifact_sha256,
        container_image_digest=candidate.container_image_digest,
        training_request_identity_sha256=candidate.training_request_identity_sha256,
        experiment_run_identity_sha256=candidate.experiment_run_identity_sha256,
        evaluation_report_sha256=candidate.evaluation_report_sha256,
        tenant_reference_sha256=evidence.tenant_reference_sha256,
        classification=evidence.classification.value,
        now=NOW,
    )
