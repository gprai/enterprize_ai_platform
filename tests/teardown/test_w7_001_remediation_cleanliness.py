"""Teardown ordering and absence-classification coverage for W7-001."""

from __future__ import annotations

import pytest
from tools.platformctl.kubernetes_lifecycle import (
    TEARDOWN_ORDER,
    KubernetesLifecycleError,
    PatchIdentity,
    PodObservation,
    RejoinObservation,
    TeardownObservation,
    classify_not_found,
    classify_pods,
    validate_delete_arguments,
    validate_patch_identity,
    validate_rejoin,
    validate_replica_progress,
    validate_teardown_observations,
)
from tools.platformctl.lifecycle_io import validate_residue_classification
from tools.platformctl.lifecycle_models import (
    ResidueClassification,
    ResidueLocation,
    ResidueStatus,
)
from tools.platformctl.live_validation import W6004Error, require_non_pass_for_limited_evidence


def test_opensearch_data_absence_precedes_namespace_and_native_absence() -> None:
    observations = tuple(
        TeardownObservation(
            phase,
            1 if phase.value.endswith("DELETE") else 0,
            1 if phase.value.endswith("DELETE") else 0,
            phase.value.endswith("ABSENCE"),
            phase.value == "TEMPORARY_TRUST_RESTORED",
            index,
            300,
            phase.value.endswith("DELETE"),
        )
        for index, phase in enumerate(TEARDOWN_ORDER, start=1)
    )
    assert validate_teardown_observations(observations) == observations
    assert TEARDOWN_ORDER.index(TEARDOWN_ORDER[1]) < TEARDOWN_ORDER.index(TEARDOWN_ORDER[-2])


def test_expected_not_found_is_absence_but_command_failure_is_not() -> None:
    assert (
        classify_not_found(
            exit_code=1, stderr="Error from server (NotFound)", expected_absence=True
        )
        == "ABSENT"
    )
    with pytest.raises(KubernetesLifecycleError):
        classify_not_found(exit_code=1, stderr="connection refused", expected_absence=True)


def test_active_terminating_and_replacement_pods_keep_uid_identity() -> None:
    digest = "sha256:" + "a" * 64
    old = PodObservation("api-old", "uid-old", True, True, digest)
    replacement = PodObservation("api-new", "uid-new", True, False, digest)
    active, terminating = classify_pods((old, replacement), expected_digest=digest)
    assert active == (replacement,)
    assert terminating == (old,)
    rejoin = RejoinObservation("uid-old", "uid-new", 25, 60, True)
    assert validate_rejoin(rejoin) == rejoin


def test_patch_identity_and_independent_hpa_maximum_are_exact() -> None:
    patch = PatchIdentity("external/scale-patch.json", "a" * 64, False, (("api-0", "uid-0"),))
    assert validate_patch_identity(patch) == patch
    assert validate_replica_progress(
        (1, 2, 3, 2), target_replicas=2, maximum_observed_replicas=3
    ) == (
        1,
        2,
        3,
        2,
    )
    with pytest.raises(KubernetesLifecycleError):
        validate_replica_progress((1, 2), target_replicas=2, maximum_observed_replicas=1)
    with pytest.raises(KubernetesLifecycleError, match="delete arguments"):
        validate_delete_arguments(("delete", "pod", "api-0", "--preconditions=uid=uid-0"))


@pytest.mark.parametrize("tail", ["kms-pending-deletion", "billing-lag"])
def test_closure_tails_cannot_be_promoted_to_pass(tail: str) -> None:
    with pytest.raises(W6004Error, match="cannot be PASS"):
        require_non_pass_for_limited_evidence(
            status="PASS",
            disposition="CLOSURE_TAIL",
        )
    assert tail


def test_repository_and_external_residue_are_classified_separately() -> None:
    records = (
        ResidueClassification(
            "reports/w7-001", ResidueLocation.REPOSITORY, ResidueStatus.ABSENT, False, "owner"
        ),
        ResidueClassification(
            "external/evidence", ResidueLocation.EXTERNAL, ResidueStatus.RETAINED, True, "owner"
        ),
    )
    assert validate_residue_classification(records) == records
