"""Security proof for W4-11 path, content and error boundaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from enterprise_ai_platform.release_rollback.errors import (
    ReleaseIdentityError,
    ReleaseUnsafePathError,
)
from enterprise_ai_platform.release_rollback.identity import (
    _validate_relative_path,
    load_release_descriptor,
)
from enterprise_ai_platform.release_rollback.state import _runtime_file

SENTINELS = (
    "PROMPT_SECRET_W4_011",
    "ANSWER_PII_W4_011",
    "EVIDENCE_TOKEN_W4_011",
    "TOOL_ARGUMENT_W4_011",
    "CREDENTIAL_W4_011",
    "EXCEPTION_DETAIL_W4_011",
)


def test_descriptors_contain_only_paths_hashes_and_finite_safe_profile_data() -> None:
    descriptors = (
        load_release_descriptor("w4-known-good-v1"),
        load_release_descriptor("w4-synthetic-regression-v1"),
    )
    captured = json.dumps(
        [item.model_dump(mode="json") for item in descriptors],
        sort_keys=True,
    )

    for sentinel in SENTINELS:
        assert sentinel not in captured
    for forbidden in (
        "tenant_id",
        "subject_id",
        "tool_arguments",
        "stack_trace",
        "chain_of_thought",
        "provider_envelope",
    ):
        assert forbidden not in captured


@pytest.mark.parametrize(
    "value",
    (
        "../active.json",
        "/absolute.json",
        "C:/absolute.json",
        "reports\\w4-release\\active.json",
        "reports/w4-release/../active.json",
        "./reports/w4-release/active.json",
    ),
)
def test_unsafe_release_paths_fail_before_runtime_access(value: str) -> None:
    with pytest.raises(ReleaseUnsafePathError):
        _validate_relative_path(value)


def test_runtime_path_boundary_rejects_traversal() -> None:
    with pytest.raises(ReleaseUnsafePathError):
        _runtime_file(Path("reports/w4-release/../active.json"))


def test_public_error_is_content_free() -> None:
    error = ReleaseIdentityError()
    assert str(error) == error.code == "release_identity_mismatch"
    assert all(sentinel not in str(error) for sentinel in SENTINELS)
