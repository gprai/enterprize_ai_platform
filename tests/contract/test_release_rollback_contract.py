"""Contract tests for strict W4-11 identity, state, report and CLI schemas."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError
from tools.releasectl import build_parser

from enterprise_ai_platform.json_contracts import DuplicateJSONKeyError, strict_json_loads
from enterprise_ai_platform.release_rollback.identity import canonical_json_bytes
from enterprise_ai_platform.release_rollback.models import (
    ActiveReleaseState,
    ArtifactFingerprint,
    CandidateProbeResult,
)


def test_strict_models_forbid_extra_fields_and_candidate_route_enablement() -> None:
    with pytest.raises(ValidationError):
        ArtifactFingerprint.model_validate(
            {"path": "requirements.txt", "sha256": "a" * 64, "extra": 1},
            strict=True,
        )
    with pytest.raises(ValidationError):
        ActiveReleaseState(
            schema_version="w4-011.active.v1",
            generation=1,
            active_release="w4-synthetic-regression-v1",
            descriptor_sha256="a" * 64,
            composition_sha256="b" * 64,
            agent_route_allowed=True,
        )
    with pytest.raises(ValidationError):
        CandidateProbeResult.model_validate(
            {
                "status": "EXPECTED_REGRESSION_DETECTED",
                "http_status": 501,
                "safe_error_code": "agent_disabled",
                "rag_calls": 1,
                "retrieval_calls": 0,
                "embedding_calls": 0,
                "provider_calls": 0,
                "graph_calls": 0,
                "approval_calls": 0,
                "tool_calls": 0,
                "network_activity": False,
            },
            strict=True,
        )


def test_canonical_json_rejects_duplicate_and_non_finite_input() -> None:
    assert canonical_json_bytes({"z": 1, "a": "é"}) == (
        '{"a":"é","z":1}\n'.encode()
    )
    with pytest.raises(DuplicateJSONKeyError):
        strict_json_loads('{"generation":1,"generation":2}')
    with pytest.raises(ValueError):
        canonical_json_bytes({"duration": float("nan")})


def test_cli_exposes_only_the_fixed_local_lifecycle_commands() -> None:
    parser = build_parser()
    for command in (
        "validate",
        "rollback-release",
        "smoke",
        "verify-clean",
        "cleanup",
        "verify-zero-residue",
    ):
        arguments = parser.parse_args([command])
        assert arguments.command == command
    rendered = json.dumps(vars(parser.parse_args(["validate"])), sort_keys=True)
    assert "endpoint" not in rendered
    assert "credential" not in rendered
