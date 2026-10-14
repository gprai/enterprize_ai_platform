"""Business behavior for reproducible, privacy-safe W9-002 experiment lineage."""

from enterprise_ai_platform.experiment_tracking import (
    ExperimentTrackingService,
    InMemoryMlflowStore,
    TenantExperimentAuthorizer,
    fingerprint,
    load_experiment_policy,
)
from tests.fakes.w9_002_experiment_tracking import (
    NOW,
    make_auth,
    make_envelope,
    make_input,
)


def test_reviewer_can_reproduce_and_compare_without_authorizing_deployment() -> None:
    auth = make_auth()
    store = InMemoryMlflowStore()
    service = ExperimentTrackingService(
        policy=load_experiment_policy(),
        authorizer=TenantExperimentAuthorizer(),
        store=store,
    )
    baseline = service.record(make_envelope(auth=auth, run_number=1), make_input(), auth, now=NOW)
    candidate = service.record(
        make_envelope(auth=auth, run_number=2),
        make_input(model_revision="model-v2", groundedness="0.980000"),
        auth,
        now=NOW,
    )

    comparison = service.compare(
        baseline.envelope.run_id,
        candidate.envelope.run_id,
        auth,
        now=NOW,
        tenant_reference_sha256=baseline.envelope.tenant_reference_sha256,
    )

    assert baseline.input_identity_sha256 == fingerprint(baseline.experiment_input)
    assert candidate.input_identity_sha256 == fingerprint(candidate.experiment_input)
    assert baseline.experiment_input.dataset.synthetic is True
    assert baseline.experiment_input.dataset.production_data is False
    assert comparison.deployment_approval == "NOT_AUTHORIZED"
    assert comparison.promotion_approval == "NOT_AUTHORIZED"
    assert {metric.name for metric in baseline.experiment_input.metrics} == {
        "citation_precision",
        "groundedness",
        "safety",
    }


def test_lineage_uses_hash_and_count_linkage_without_raw_golden_set_content() -> None:
    experiment_input = make_input()
    rendered = experiment_input.model_dump_json().casefold()

    assert experiment_input.dataset.case_count == 39
    assert len(experiment_input.dataset.case_inventory_sha256) == 64
    for forbidden in ("question_text", "expected_facts", "answer_text", "evidence_text"):
        assert forbidden not in rendered
