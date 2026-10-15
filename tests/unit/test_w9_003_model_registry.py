"""Unit tests for strict W9-003 package identities and model cards."""

import pytest

from enterprise_ai_platform.model_registry import ModelCard, canonical_bytes, fingerprint
from tests.fakes.w9_003_model_registry import make_package


def test_package_identity_is_deterministic_and_newline_terminated() -> None:
    package = make_package()

    assert fingerprint(package) == fingerprint(package)
    assert canonical_bytes(package).endswith(b"\n")
    assert not canonical_bytes(package).endswith(b"\n\n")


def test_mutable_model_version_and_reordered_card_statements_fail_closed() -> None:
    card = make_package().model_card
    payload = card.model_dump(mode="python")
    payload["model_version"] = "latest"
    with pytest.raises(ValueError, match="immutable"):
        ModelCard.model_validate(payload, strict=True)

    payload = card.model_dump(mode="python")
    payload["limitations"] = ("z limitation", "a limitation")
    with pytest.raises(ValueError, match="sorted and unique"):
        ModelCard.model_validate(payload, strict=True)


def test_artifact_or_evaluation_substitution_is_rejected() -> None:
    package = make_package()
    payload = package.model_dump(mode="python")
    payload["artifact"]["sha256"] = "0" * 64
    with pytest.raises(ValueError, match="training result and model artifact"):
        type(package).model_validate(payload, strict=True)

    payload = package.model_dump(mode="python")
    payload["experiment_run"]["experiment_input"]["evaluation"]["baseline_comparison_status"] = (
        "NO_APPROVED_BASELINE"
    )
    payload["experiment_run_identity_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="run input identity"):
        type(package).model_validate(payload, strict=True)


def test_package_schema_contains_no_raw_content_fields() -> None:
    rendered = str(type(make_package()).model_json_schema()).casefold()

    for required in ("artifact", "container", "code", "evaluation", "model_card"):
        assert required in rendered
    for forbidden in ("prompt_text", "response_text", "raw_content", "credential_value"):
        assert forbidden not in rendered
