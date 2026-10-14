"""Unit tests for strict W9-002 lineage identities and privacy gates."""

from decimal import Decimal

import pytest

from enterprise_ai_platform.experiment_tracking import (
    ArtifactReference,
    ExperimentMetric,
    ExperimentParameter,
    ExperimentValidationError,
    MetricUnit,
    canonical_bytes,
    fingerprint,
    validate_privacy_safe_input,
)
from tests.fakes.w9_002_experiment_tracking import make_input


def test_canonical_identity_is_deterministic_and_newline_terminated() -> None:
    experiment_input = make_input()

    assert fingerprint(experiment_input) == fingerprint(experiment_input)
    assert canonical_bytes(experiment_input).endswith(b"\n")
    assert not canonical_bytes(experiment_input).endswith(b"\n\n")


def test_duplicate_or_reordered_values_fail_closed() -> None:
    payload = make_input().model_dump(mode="python")
    payload["metrics"] = tuple(reversed(payload["metrics"]))

    with pytest.raises(ValueError, match="sorted and unique"):
        type(make_input()).model_validate(payload, strict=True)


def test_non_finite_and_out_of_range_metrics_are_rejected() -> None:
    with pytest.raises(ValueError, match="finite"):
        ExperimentMetric(
            name="latency_ms",
            value=Decimal("NaN"),
            unit=MetricUnit.MILLISECONDS,
            derivation="test.v1",
        )
    with pytest.raises(ValueError, match="between zero and one"):
        ExperimentMetric(
            name="groundedness",
            value=Decimal("1.1"),
            unit=MetricUnit.RATIO,
            derivation="test.v1",
        )


def test_secret_and_raw_content_parameter_names_are_rejected_before_storage() -> None:
    for key in ("api_key", "raw_prompt", "model_response", "private_key"):
        unsafe = make_input(parameters=(ExperimentParameter(key=key, value="redacted"),))
        with pytest.raises(ExperimentValidationError, match="unsafe"):
            validate_privacy_safe_input(unsafe)


def test_artifact_path_traversal_is_rejected() -> None:
    with pytest.raises(ValueError, match="safe relative"):
        ArtifactReference(
            kind="evaluation_report",
            path="../raw.json",
            sha256="a" * 64,
            classification="INTERNAL",
        )
