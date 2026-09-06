"""Unit coverage for canonical W4-11 release identity."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from enterprise_ai_platform.release_rollback import identity as identity_module
from enterprise_ai_platform.release_rollback.errors import ReleaseIdentityError
from enterprise_ai_platform.release_rollback.identity import (
    APPROVED_ARTIFACT_COUNT,
    APPROVED_ARTIFACT_PATHS,
    APPROVED_COMPOSITION_SHA256,
    DESCRIPTOR_PATHS,
    REPOSITORY_ROOT,
    artifact_composition_sha256,
    canonical_json_bytes,
    descriptor_sha256,
    load_release_descriptor,
    validate_current_checkout,
    validate_release_pair,
)
from enterprise_ai_platform.release_rollback.models import (
    ArtifactFingerprint,
    ReleaseDescriptor,
)


def test_known_good_and_regression_descriptors_are_canonical_and_exact() -> None:
    known_good, regression = validate_release_pair()

    assert known_good.artifact_count == APPROVED_ARTIFACT_COUNT == 99
    assert tuple(item.path for item in known_good.artifacts) == (APPROVED_ARTIFACT_PATHS)
    assert known_good.artifacts == regression.artifacts
    assert known_good.composition_sha256 == APPROVED_COMPOSITION_SHA256
    assert artifact_composition_sha256(known_good) == APPROVED_COMPOSITION_SHA256
    assert descriptor_sha256(known_good) != descriptor_sha256(regression)
    for version, relative in DESCRIPTOR_PATHS.items():
        descriptor = load_release_descriptor(version)
        payload = (REPOSITORY_ROOT / relative).read_bytes()
        assert not payload.startswith(b"\xef\xbb\xbf")
        assert payload == canonical_json_bytes(descriptor.model_dump(mode="json"))
        assert payload.endswith(b"\n") and not payload.endswith(b"\n\n")


def test_release_profiles_differ_only_by_the_approved_safe_regression() -> None:
    known_good, regression = validate_release_pair()
    assert known_good.agent_enabled is True
    assert known_good.expected_gate == "PASS"
    assert known_good.expected_safe_error_code is None
    assert regression.agent_enabled is False
    assert regression.regression_profile == "w4-011.agent-route-disabled.v1"
    assert regression.expected_gate == "FAIL"
    assert regression.expected_safe_error_code == "agent_disabled"


def test_historical_loading_and_current_checkout_verification_are_separate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor = load_release_descriptor("w4-known-good-v1")

    monkeypatch.setattr(identity_module, "hash_file", lambda _: "0" * 64)

    assert load_release_descriptor("w4-known-good-v1") == descriptor
    with pytest.raises(ReleaseIdentityError):
        validate_current_checkout(descriptor)


def test_schema_rejects_extra_reordered_duplicate_and_unsafe_artifacts() -> None:
    known_good = load_release_descriptor("w4-known-good-v1")
    values = known_good.model_dump(mode="python")

    with_extra = dict(values, unexpected="forbidden")
    try:
        ReleaseDescriptor.model_validate(with_extra, strict=True)
    except ValidationError:
        pass
    else:
        raise AssertionError("extra release field must be rejected")

    reordered = ReleaseDescriptor.model_validate(
        dict(values, artifacts=tuple(reversed(known_good.artifacts))),
        strict=True,
    )
    assert artifact_composition_sha256(reordered) != (APPROVED_COMPOSITION_SHA256)

    duplicated = dict(
        values,
        artifacts=known_good.artifacts[:-1] + (known_good.artifacts[-2],),
    )
    try:
        ReleaseDescriptor.model_validate(duplicated, strict=True)
    except ValidationError:
        pass
    else:
        raise AssertionError("duplicate artifact inventory must be rejected")

    try:
        ArtifactFingerprint(
            path="configs/../protected.json",
            sha256="a" * 64,
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("unsafe artifact path must be rejected")


def test_release_control_package_is_not_an_application_payload_input() -> None:
    assert all(
        not Path(path).is_relative_to("src/enterprise_ai_platform/release_rollback")
        for path in APPROVED_ARTIFACT_PATHS
    )
