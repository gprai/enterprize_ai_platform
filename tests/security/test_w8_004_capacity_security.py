"""Security and privacy checks for W8-004 aggregate evidence."""

from datetime import UTC, datetime

import pytest

from enterprise_ai_platform.capacity import (
    CapacitySample,
    CapacityValidationError,
    canonical_json,
    load_capacity_policy,
)
from tests.fakes.w8_004_capacity import valid_sample


def test_raw_tenant_content_and_credentials_are_forbidden() -> None:
    policy = load_capacity_policy()
    payload = valid_sample(policy).model_dump(mode="python")

    for forbidden in ("tenant_id", "request_payload", "authorization", "api_key"):
        candidate = dict(payload)
        candidate[forbidden] = "must-not-be-recorded"
        with pytest.raises(ValueError):
            CapacitySample.model_validate(candidate, strict=True)


def test_duplicate_policy_keys_are_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    duplicate = tmp_path / "duplicate.yaml"
    duplicate.write_text(
        "schema_version: w8-004.capacity-cost-policy.v1\nschema_version: duplicate\n",
        encoding="utf-8",
    )

    with pytest.raises(CapacityValidationError, match="duplicate YAML key"):
        load_capacity_policy(duplicate)


def test_yaml_aliases_are_rejected(tmp_path) -> None:  # type: ignore[no-untyped-def]
    alias = tmp_path / "alias.yaml"
    alias.write_text("value: &shared one\ncopy: *shared\n", encoding="utf-8")

    with pytest.raises(CapacityValidationError, match="aliases"):
        load_capacity_policy(alias)


def test_aggregate_serialization_contains_no_raw_content_fields() -> None:
    rendered = canonical_json(valid_sample(load_capacity_policy()))

    for forbidden in ("tenant_id", "request_payload", "authorization", "credential"):
        assert forbidden not in rendered.casefold()
    assert datetime.now(tz=UTC).tzinfo is not None
